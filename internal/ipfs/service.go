// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package ipfs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"
)

const readinessVersion = 1

var (
	// ErrServiceAlreadyRunning means another process owns the boot-scoped IPFS
	// service lease.
	ErrServiceAlreadyRunning = errors.New("IPFS service is already running")
	// ErrFullKuboStopped means the maintained node ceased to be usable while
	// this service still held semantic readiness.
	ErrFullKuboStopped = errors.New("full Kubo node stopped")
)

// KuboLifecycle is the maintained adapter's semantic health and termination
// contract. Ready must actively probe the repository, block/DAG datastore,
// pin service, and pre-signed IPNS injection boundary; a descriptor alone is
// not readiness evidence. Done must signal once those facilities become
// unusable or the node exits.
type KuboLifecycle interface {
	Ready(context.Context) error
	Done() <-chan error
}

// ReadinessRecord is boot-scoped semantic readiness evidence. It exposes only
// public identity and integration metadata.
type ReadinessRecord struct {
	Version              int    `json:"version"`
	Service              string `json:"service"`
	Ready                bool   `json:"ready"`
	Product              string `json:"product"`
	KuboVersion          string `json:"kubo_version"`
	RepositoryPath       string `json:"repository_path"`
	IPNSName             string `json:"ipns_name"`
	PeerID               string `json:"peer_id"`
	ULA                   string `json:"ula"`
	PublicationState     int    `json:"publication_state_version"`
	SignedRecordBoundary string `json:"signed_record_boundary"`
}

// Service owns one validated full-Kubo seam, public publisher, and boot-scoped
// readiness record. No internal control listener is invented while D-012 is
// unresolved.
type Service struct {
	node           FullKuboNode
	publisher      *Publisher
	readinessMu    sync.RWMutex
	readiness      ReadinessRecord
	runtimeRoot    *os.Root
	runtimePath    string
	readinessBytes []byte
	lease          *os.File
	nodeDone       <-chan error
	closed         chan struct{}
	closeOnce      sync.Once
	closeErr       error
}

// StartService validates full-Kubo identity coherence, opens crash-safe
// publication state, and publishes readiness only after every boundary is
// usable. It takes ownership of node even when startup fails.
func StartService(
	ctx context.Context,
	config Config,
	signer *TPMIPNSSigner,
	node FullKuboNode,
	clock Clock,
) (*Service, error) {
	if isNil(ctx) {
		return nil, errors.New("IPFS service context is required")
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if signer == nil {
		return nil, errors.New("TPM IPNS signer is required")
	}
	if isNil(node) {
		return nil, errors.New("full Kubo node is required")
	}
	closeNodeOnError := true
	defer func() {
		if closeNodeOnError {
			_ = node.Close()
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := proveIPNSSigner(ctx, signer); err != nil {
		return nil, err
	}
	descriptor, err := node.Describe(ctx)
	if err != nil {
		return nil, fmt.Errorf("describe full Kubo node: %w", err)
	}
	if err := validateNodeDescriptor(descriptor, config, signer); err != nil {
		return nil, err
	}
	lifecycle, ok := node.(KuboLifecycle)
	if !ok {
		return nil, errors.New(
			"full Kubo adapter has no semantic lifecycle contract",
		)
	}
	if err := lifecycle.Ready(ctx); err != nil {
		return nil, fmt.Errorf("full Kubo node is not ready: %w", err)
	}
	nodeDone := lifecycle.Done()
	if nodeDone == nil {
		return nil, errors.New(
			"full Kubo lifecycle returned a nil termination channel",
		)
	}
	if err := pollKuboTermination(nodeDone); err != nil {
		return nil, err
	}
	store, err := NewFilePublicationStateStore(config.RepositoryPath)
	if err != nil {
		return nil, err
	}
	publisher, err := NewPublisher(
		node,
		signer,
		store,
		config.RecordPolicy,
		clock,
	)
	if err != nil {
		return nil, err
	}
	state, err := store.Load()
	if err != nil {
		return nil, fmt.Errorf("load IPFS publication state: %w", err)
	}
	if err := publisher.validateStateForSigner(state); err != nil {
		return nil, err
	}
	if err := pollKuboTermination(nodeDone); err != nil {
		return nil, err
	}

	runtimeRoot, err := openSecureDirectory(config.RuntimePath)
	if err != nil {
		return nil, fmt.Errorf("open IPFS runtime directory: %w", err)
	}
	closeRuntimeOnError := true
	defer func() {
		if closeRuntimeOnError {
			_ = runtimeRoot.Close()
		}
	}()
	lease, err := acquireServiceLease(runtimeRoot)
	if err != nil {
		return nil, err
	}
	releaseLeaseOnError := true
	defer func() {
		if releaseLeaseOnError {
			releasePublicationLock(lease)
		}
	}()
	if err := validateOptionalRegularFile(
		runtimeRoot,
		readinessFilename,
	); err != nil {
		return nil, err
	}
	readiness := ReadinessRecord{
		Version:              readinessVersion,
		Service:              "ipfs",
		Ready:                true,
		Product:              descriptor.Product,
		KuboVersion:          descriptor.Version,
		RepositoryPath:       descriptor.RepositoryPath,
		IPNSName:             signer.Name(),
		PeerID:               signer.PeerID().String(),
		ULA:                  signer.ULA().String(),
		PublicationState:     PublicationStateVersion,
		SignedRecordBoundary: SignedRecordBoundaryV1,
	}
	encoded, err := json.MarshalIndent(readiness, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode IPFS readiness: %w", err)
	}
	encoded = append(encoded, '\n')
	if err := atomicReplaceInRoot(
		runtimeRoot,
		readinessFilename,
		encoded,
	); err != nil {
		var cleanupErr error
		if errors.Is(err, ErrPublicationStateDurabilityUncertain) {
			cleanupErr = removeReadinessIfOwned(runtimeRoot, encoded)
		}
		if cleanupErr != nil {
			return nil, errors.Join(
				fmt.Errorf("publish IPFS readiness: %w", err),
				fmt.Errorf(
					"remove uncertain IPFS readiness: %w",
					cleanupErr,
				),
			)
		}
		return nil, fmt.Errorf("publish IPFS readiness: %w", err)
	}
	if err := requireDirectoryStillAtPath(
		runtimeRoot,
		config.RuntimePath,
	); err != nil {
		_ = removeReadinessIfOwned(runtimeRoot, encoded)
		return nil, err
	}
	if err := pollKuboTermination(nodeDone); err != nil {
		cleanupErr := removeReadinessIfOwned(runtimeRoot, encoded)
		return nil, errors.Join(err, cleanupErr)
	}
	closeNodeOnError = false
	closeRuntimeOnError = false
	releaseLeaseOnError = false
	service := &Service{
		node:           node,
		publisher:      publisher,
		readiness:      readiness,
		runtimeRoot:    runtimeRoot,
		runtimePath:    config.RuntimePath,
		readinessBytes: encoded,
		lease:          lease,
		nodeDone:       nodeDone,
		closed:         make(chan struct{}),
	}
	go service.monitorKubo()
	return service, nil
}

// Publisher returns the public-only Trust outbox consumer.
func (s *Service) Publisher() *Publisher {
	if s == nil {
		return nil
	}
	return s.publisher
}

// Readiness returns boot-scoped public readiness metadata.
func (s *Service) Readiness() ReadinessRecord {
	if s == nil {
		return ReadinessRecord{}
	}
	s.readinessMu.RLock()
	defer s.readinessMu.RUnlock()
	return s.readiness
}

// Run remains ready until cancellation or Close. Service independently
// monitors maintained-Kubo termination, so readiness is withdrawn even when
// no caller is currently blocked in Run.
func (s *Service) Run(ctx context.Context) error {
	if s == nil {
		return errors.New("IPFS service is required")
	}
	if isNil(ctx) {
		return errors.New("IPFS service context is required")
	}
	select {
	case <-ctx.Done():
		return s.Close()
	case <-s.closed:
		return s.closeErr
	}
}

func pollKuboTermination(done <-chan error) error {
	select {
	case nodeErr, ok := <-done:
		return kuboTerminationError(nodeErr, ok)
	default:
		return nil
	}
}

func kuboTerminationError(nodeErr error, ok bool) error {
	if !ok || nodeErr == nil {
		return ErrFullKuboStopped
	}
	return fmt.Errorf("%w: %v", ErrFullKuboStopped, nodeErr)
}

func (s *Service) monitorKubo() {
	select {
	case nodeErr, ok := <-s.nodeDone:
		_ = s.stop(kuboTerminationError(nodeErr, ok))
	case <-s.closed:
	}
}

// Close removes only this instance's readiness bytes and closes Kubo.
func (s *Service) Close() error {
	if s == nil {
		return nil
	}
	return s.stop(nil)
}

func (s *Service) stop(cause error) error {
	s.closeOnce.Do(func() {
		var errs []error
		if cause != nil {
			errs = append(errs, cause)
		}
		s.readinessMu.Lock()
		s.readiness.Ready = false
		s.readinessMu.Unlock()
		if err := removeReadinessIfOwned(
			s.runtimeRoot,
			s.readinessBytes,
		); err != nil {
			errs = append(errs, err)
		}
		if err := requireDirectoryStillAtPath(
			s.runtimeRoot,
			s.runtimePath,
		); err != nil {
			errs = append(errs, err)
		}
		releasePublicationLock(s.lease)
		s.lease = nil
		if err := s.runtimeRoot.Close(); err != nil {
			errs = append(errs, fmt.Errorf(
				"close IPFS runtime directory: %w",
				err,
			))
		}
		if err := s.node.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close full Kubo node: %w", err))
		}
		s.closeErr = errors.Join(errs...)
		close(s.closed)
	})
	<-s.closed
	return s.closeErr
}

func acquireServiceLease(root *os.Root) (*os.File, error) {
	if err := validateOptionalRegularFile(root, serviceLockFilename); err != nil {
		return nil, err
	}
	lease, err := root.OpenFile(
		serviceLockFilename,
		os.O_CREATE|os.O_RDWR,
		0o600,
	)
	if err != nil {
		return nil, fmt.Errorf("open IPFS service lock: %w", err)
	}
	opened, err := lease.Stat()
	if err != nil {
		_ = lease.Close()
		return nil, fmt.Errorf("inspect IPFS service lock: %w", err)
	}
	pathInfo, err := root.Lstat(serviceLockFilename)
	if err != nil ||
		!os.SameFile(opened, pathInfo) {
		_ = lease.Close()
		return nil, errors.New("IPFS service lock changed while opening")
	}
	if err := validateOwnedRegularFile(serviceLockFilename, opened); err != nil {
		_ = lease.Close()
		return nil, err
	}
	if err := flock(lease, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lease.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) ||
			errors.Is(err, syscall.EAGAIN) {
			return nil, ErrServiceAlreadyRunning
		}
		return nil, fmt.Errorf("lock IPFS service runtime: %w", err)
	}
	return lease, nil
}

func removeReadinessIfOwned(root *os.Root, expected []byte) error {
	info, err := root.Lstat(readinessFilename)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect IPFS readiness: %w", err)
	}
	if err := validateOwnedRegularFile(readinessFilename, info); err != nil {
		return err
	}
	file, err := root.Open(readinessFilename)
	if err != nil {
		return fmt.Errorf("open IPFS readiness: %w", err)
	}
	content, readErr := io.ReadAll(
		io.LimitReader(file, int64(len(expected)+1)),
	)
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	if !bytes.Equal(content, expected) {
		return errors.New(
			"refusing to remove readiness owned by another IPFS instance",
		)
	}
	if err := root.Remove(readinessFilename); err != nil {
		return fmt.Errorf("remove IPFS readiness: %w", err)
	}
	directory, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("open IPFS runtime directory for sync: %w", err)
	}
	syncErr := directory.Sync()
	closeErr = directory.Close()
	return errors.Join(syncErr, closeErr)
}
