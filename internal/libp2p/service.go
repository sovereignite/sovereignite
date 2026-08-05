// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package libp2p

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"

	"github.com/libp2p/go-libp2p/core/peer"
)

const (
	endpointRecordVersion = 1
	minimumHighPort       = 1024
)

var (
	// ErrServiceAlreadyRunning means another process owns the boot-scoped
	// identity service lease.
	ErrServiceAlreadyRunning = errors.New("identity service is already running")
	// ErrHostUnavailable means no fully initialized real libp2p host is
	// available. Readiness must never be published for the local seam alone.
	ErrHostUnavailable = errors.New("real libp2p host is unavailable")
)

// RunningHost is the lifetime handle for an actual initialized libp2p host,
// including its required transports. A readiness-only TCP listener does not
// satisfy this interface's contract.
type RunningHost interface {
	ID() peer.ID
	Close() error
}

// HostLauncher must return only after a real identity-bound libp2p host is
// ready. In particular, callers must not treat this interface as a software
// fallback for TPM signing or as permission to export Identity.PrivateKey().
type HostLauncher interface {
	Launch(context.Context, *Identity) (RunningHost, error)
}

// EndpointRecord describes the boot-scoped local readiness listener. It does
// not advertise an RPC protocol.
type EndpointRecord struct {
	Version          int    `json:"version"`
	Service          string `json:"service"`
	BootID           string `json:"boot_id"`
	InstanceNonce    string `json:"instance_nonce"`
	PID              int    `json:"pid"`
	Network          string `json:"network"`
	Address          string `json:"address"`
	Port             uint16 `json:"port"`
	ExpectedIdentity string `json:"expected_identity"`
}

// Service owns the initialized identity and its boot-scoped readiness
// listener.
type Service struct {
	identity       *Identity
	listener       net.Listener
	endpoint       EndpointRecord
	runtimeRoot    *os.Root
	endpointName   string
	endpointBytes  []byte
	endpointInfo   os.FileInfo
	lease          *runtimeLease
	host           RunningHost
	closed         chan struct{}
	closeOnce      sync.Once
	closeErr       error
}

// Start initializes the stable identity, binds 127.0.0.1 on an ephemeral TCP
// port, and atomically publishes the endpoint record. No QUIC transport or
// application RPC is created.
func Start(
	ctx context.Context,
	config Config,
	key TPMSigningKey,
	hostLauncher HostLauncher,
	hostnameSetter HostnameSetter,
) (*Service, error) {
	if isNil(ctx) {
		return nil, errors.New("context is required")
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if isNil(hostLauncher) {
		return nil, ErrHostUnavailable
	}
	if isNil(hostnameSetter) {
		return nil, errors.New("hostname setter is required")
	}
	identity, err := prepareIdentity(ctx, key)
	if err != nil {
		return nil, err
	}
	host, err := hostLauncher.Launch(ctx, identity)
	if err != nil {
		var closeErr error
		if !isNil(host) {
			closeErr = host.Close()
		}
		return nil, errors.Join(
			ErrHostUnavailable,
			fmt.Errorf("launch real libp2p host: %w", err),
			wrapCloseError("close partially launched libp2p host", closeErr),
		)
	}
	if isNil(host) {
		return nil, errors.Join(
			ErrHostUnavailable,
			errors.New("host launcher returned no running host"),
		)
	}
	if host.ID() != identity.PeerID {
		closeErr := host.Close()
		return nil, errors.Join(
			ErrHostUnavailable,
			errors.New("running libp2p host identity does not match the TPM identity"),
			wrapCloseError("close identity-mismatched libp2p host", closeErr),
		)
	}
	closeHostOnError := true
	defer func() {
		if closeHostOnError {
			_ = host.Close()
		}
	}()
	runtimeRootPath := filepath.Clean(config.RuntimeRoot)
	runtimeRoot, err := openPrivateDirectory(runtimeRootPath)
	if err != nil {
		return nil, fmt.Errorf("create identity runtime root: %w", err)
	}
	closeRootOnError := true
	defer func() {
		if closeRootOnError {
			_ = runtimeRoot.Close()
		}
	}()
	lease, err := acquireRuntimeLease(runtimeRoot, runtimeLockFilename)
	if err != nil {
		return nil, err
	}
	releaseLeaseOnError := true
	defer func() {
		if releaseLeaseOnError {
			_ = lease.Close()
		}
	}()

	if err := activateIdentity(ctx, config, identity, hostnameSetter); err != nil {
		return nil, err
	}
	var listenConfig net.ListenConfig
	listener, err := listenConfig.Listen(ctx, "tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("bind identity readiness listener: %w", err)
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = listener.Close()
		}
	}()

	address, err := netip.ParseAddrPort(listener.Addr().String())
	if err != nil {
		return nil, fmt.Errorf("parse readiness listener address: %w", err)
	}
	if address.Addr() != netip.MustParseAddr("127.0.0.1") ||
		address.Port() < minimumHighPort {
		return nil, errors.New("readiness listener is not a high IPv4 loopback endpoint")
	}
	bootID, err := currentBootID()
	if err != nil {
		return nil, err
	}
	instanceNonce, err := newInstanceNonce()
	if err != nil {
		return nil, err
	}
	record := EndpointRecord{
		Version:          endpointRecordVersion,
		Service:          "identity",
		BootID:           bootID,
		InstanceNonce:    instanceNonce,
		PID:              os.Getpid(),
		Network:          "tcp4",
		Address:          address.Addr().String(),
		Port:             address.Port(),
		ExpectedIdentity: identity.Name,
	}
	encoded, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode identity endpoint record: %w", err)
	}
	encoded = append(encoded, '\n')

	endpointInfo, err := atomicReplaceTracked(
		runtimeRoot,
		endpointRecordFilename,
		encoded,
		0o600,
	)
	if err != nil {
		cleanupErr := removeIfOwnedFileMatches(
			runtimeRoot,
			endpointRecordFilename,
			encoded,
			endpointInfo,
		)
		return nil, errors.Join(
			fmt.Errorf("publish identity endpoint: %w", err),
			cleanupErr,
		)
	}
	if err := requireOwnedRegularFile(
		runtimeRoot,
		endpointRecordFilename,
		endpointInfo,
		0o600,
		int64(len(encoded)),
	); err != nil {
		cleanupErr := removeIfOwnedFileMatches(
			runtimeRoot,
			endpointRecordFilename,
			encoded,
			endpointInfo,
		)
		return nil, errors.Join(
			fmt.Errorf("verify published identity endpoint: %w", err),
			cleanupErr,
		)
	}
	if err := requireRootStillAtPath(runtimeRoot, runtimeRootPath); err != nil {
		cleanupErr := removeIfOwnedFileMatches(
			runtimeRoot,
			endpointRecordFilename,
			encoded,
			endpointInfo,
		)
		return nil, errors.Join(
			fmt.Errorf("verify published identity runtime root: %w", err),
			cleanupErr,
		)
	}

	closeOnError = false
	closeRootOnError = false
	releaseLeaseOnError = false
	closeHostOnError = false
	return &Service{
		identity:      identity,
		listener:      listener,
		endpoint:      record,
		runtimeRoot:   runtimeRoot,
		endpointName:  endpointRecordFilename,
		endpointBytes: encoded,
		endpointInfo:  endpointInfo,
		lease:          lease,
		host:           host,
		closed:        make(chan struct{}),
	}, nil
}

// Identity returns the initialized lifetime-stable identity.
func (s *Service) Identity() *Identity {
	if s == nil {
		return nil
	}
	return s.identity
}

// Endpoint returns the currently published readiness endpoint record.
func (s *Service) Endpoint() EndpointRecord {
	if s == nil {
		return EndpointRecord{}
	}
	return s.endpoint
}

// Run remains ready until cancellation or Close. Connections are accepted and
// immediately closed without reading or writing bytes so this listener cannot
// accidentally establish a public protocol before generated API bindings
// exist.
func (s *Service) Run(ctx context.Context) error {
	if s == nil {
		return errors.New("identity service is required")
	}
	if isNil(ctx) {
		return errors.New("context is required")
	}
	watcherDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = s.Close()
		case <-s.closed:
		case <-watcherDone:
		}
	}()
	defer close(watcherDone)

	for {
		connection, err := s.listener.Accept()
		if err == nil {
			_ = connection.Close()
			continue
		}
		select {
		case <-s.closed:
			return s.closeErr
		default:
		}
		closeErr := s.Close()
		return errors.Join(fmt.Errorf("accept identity readiness connection: %w", err), closeErr)
	}
}

// Close stops readiness and removes only the endpoint record still owned by
// this service instance.
func (s *Service) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		var errs []error
		if err := s.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, fmt.Errorf("close identity readiness listener: %w", err))
		}
		if err := s.host.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close real libp2p host: %w", err))
		}
		if err := removeIfOwnedFileMatches(
			s.runtimeRoot,
			s.endpointName,
			s.endpointBytes,
			s.endpointInfo,
		); err != nil {
			errs = append(errs, fmt.Errorf("remove identity endpoint: %w", err))
		}
		if err := s.lease.Close(); err != nil {
			errs = append(errs, fmt.Errorf("release identity service lease: %w", err))
		}
		if err := s.runtimeRoot.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close identity runtime root: %w", err))
		}
		s.closeErr = errors.Join(errs...)
		close(s.closed)
	})
	<-s.closed
	return s.closeErr
}

type runtimeLease struct {
	file *os.File
}

func acquireRuntimeLease(
	root *os.Root,
	name string,
) (*runtimeLease, error) {
	if info, err := root.Lstat(name); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, errors.New("identity service lock is not a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect identity service lock: %w", err)
	}
	file, err := root.OpenFile(name, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open identity service lock: %w", err)
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = file.Close()
		}
	}()

	fileInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat opened identity service lock: %w", err)
	}
	pathInfo, err := root.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("stat identity service lock path: %w", err)
	}
	if !fileInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(fileInfo, pathInfo) {
		return nil, errors.New("identity service lock changed while opening")
	}
	if err := requireEffectiveUserOwner(name, fileInfo); err != nil {
		return nil, err
	}
	if fileInfo.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf(
			"identity service lock permissions are %o, want 600",
			fileInfo.Mode().Perm(),
		)
	}
	if err := flock(file, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) ||
			errors.Is(err, syscall.EAGAIN) {
			return nil, ErrServiceAlreadyRunning
		}
		return nil, fmt.Errorf("lock identity service runtime: %w", err)
	}
	lockedInfo, err := file.Stat()
	if err != nil {
		unlockErr := flock(file, syscall.LOCK_UN)
		return nil, errors.Join(
			fmt.Errorf("stat locked identity service file: %w", err),
			unlockErr,
		)
	}
	lockedPathInfo, err := root.Lstat(name)
	if err != nil || lockedPathInfo.Mode()&os.ModeSymlink != 0 ||
		!lockedPathInfo.Mode().IsRegular() ||
		!os.SameFile(lockedInfo, lockedPathInfo) {
		unlockErr := flock(file, syscall.LOCK_UN)
		if err != nil {
			return nil, errors.Join(
				fmt.Errorf("reinspect locked identity service path: %w", err),
				unlockErr,
			)
		}
		return nil, errors.Join(
			errors.New("identity service lock changed while acquiring ownership"),
			unlockErr,
		)
	}
	if err := requireEffectiveUserOwner(name, lockedInfo); err != nil {
		unlockErr := flock(file, syscall.LOCK_UN)
		return nil, errors.Join(err, unlockErr)
	}
	if lockedInfo.Mode().Perm() != 0o600 {
		unlockErr := flock(file, syscall.LOCK_UN)
		return nil, errors.Join(
			fmt.Errorf(
				"locked identity service permissions are %o, want 600",
				lockedInfo.Mode().Perm(),
			),
			unlockErr,
		)
	}
	closeOnError = false
	return &runtimeLease{file: file}, nil
}

func (lease *runtimeLease) Close() error {
	if lease == nil || lease.file == nil {
		return nil
	}
	unlockErr := flock(lease.file, syscall.LOCK_UN)
	closeErr := lease.file.Close()
	lease.file = nil
	return errors.Join(unlockErr, closeErr)
}

func flock(file *os.File, operation int) error {
	for {
		err := syscall.Flock(int(file.Fd()), operation)
		if !errors.Is(err, syscall.EINTR) {
			return err
		}
	}
}

var fallbackBootID struct {
	once sync.Once
	id   string
	err  error
}

func currentBootID() (string, error) {
	content, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err == nil {
		bootID := strings.TrimSpace(string(content))
		if !isCanonicalUUID(bootID) {
			return "", errors.New("system boot ID is not a canonical UUID")
		}
		return bootID, nil
	}
	if runtime.GOOS == "linux" {
		return "", fmt.Errorf("read system boot ID: %w", err)
	}

	// Non-Linux development hosts do not expose Linux's boot_id file. A
	// process-scoped UUID preserves restart/staleness behavior for local tests;
	// production Flatcar hosts always use the kernel boot ID above.
	fallbackBootID.once.Do(func() {
		fallbackBootID.id, fallbackBootID.err = newUUID()
	})
	if fallbackBootID.err != nil {
		return "", fmt.Errorf("create development boot ID: %w", fallbackBootID.err)
	}
	return fallbackBootID.id, nil
}

func newInstanceNonce() (string, error) {
	random := make([]byte, 16)
	if _, err := cryptorand.Read(random); err != nil {
		return "", fmt.Errorf("generate process instance nonce: %w", err)
	}
	return hex.EncodeToString(random), nil
}

func newUUID() (string, error) {
	random := make([]byte, 16)
	if _, err := cryptorand.Read(random); err != nil {
		return "", err
	}
	random[6] = random[6]&0x0f | 0x40
	random[8] = random[8]&0x3f | 0x80
	return fmt.Sprintf(
		"%x-%x-%x-%x-%x",
		random[0:4],
		random[4:6],
		random[6:8],
		random[8:10],
		random[10:16],
	), nil
}

func isCanonicalUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		switch index {
		case 8, 13, 18, 23:
			if character != '-' {
				return false
			}
		default:
			if !((character >= '0' && character <= '9') ||
				(character >= 'a' && character <= 'f')) {
				return false
			}
		}
	}
	return true
}
