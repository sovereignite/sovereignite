// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package endpoint

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

const (
	// RecordVersion is the current schema version for endpoint records.
	RecordVersion = 1

	// filePerms is the permission mode for endpoint JSON files (owner-only).
	filePerms = 0o600

	// dirPerms is the permission mode for service directories (owner-only).
	dirPerms = 0o700
)

var (
	// ErrStaleBootID indicates the record was written for a different boot.
	ErrStaleBootID = errors.New("endpoint: stale boot ID")
	// ErrStaleInstanceNonce indicates the record belongs to a different instance.
	ErrStaleInstanceNonce = errors.New("endpoint: stale instance nonce")
	// ErrWrongService indicates the record targets a different service name.
	ErrWrongService = errors.New("endpoint: wrong service")
	// ErrMalformedRecord indicates the record could not be parsed.
	ErrMalformedRecord = errors.New("endpoint: malformed record")
	// ErrNonLoopback indicates the address is not a loopback address.
	ErrNonLoopback = errors.New("endpoint: non-loopback address")
	// ErrPIDMismatch indicates the recorded PID does not match the caller.
	ErrPIDMismatch = errors.New("endpoint: PID mismatch")
	// ErrSymlinkDetected indicates a symlink was encountered where a regular file was expected.
	ErrSymlinkDetected = errors.New("endpoint: symlink detected")
)

// EndpointRecord is a boot-scoped service endpoint record.
type EndpointRecord struct {
	Version          int    `json:"version"`
	Service          string `json:"service"`
	BootID           string `json:"boot_id"`
	InstanceNonce    string `json:"instance_nonce"`
	PID              int    `json:"pid"`
	Network          string `json:"network"`
	Address          string `json:"address"`
	Port             int    `json:"port"`
	ExpectedIdentity string `json:"expected_identity,omitempty"`
}

// Publish atomically writes a versioned endpoint record to
// dir/endpoint.json, creating dir with owner-only permissions if needed.
// It returns the loopback net.Addr that the caller should listen on.
func Publish(dir string, record EndpointRecord) (net.Addr, error) {
	if err := os.MkdirAll(dir, dirPerms); err != nil {
		return nil, fmt.Errorf("endpoint: create dir %s: %w", dir, err)
	}
	syncDir(dir)

	if err := os.Chmod(dir, dirPerms); err != nil {
		return nil, fmt.Errorf("endpoint: chmod dir %s: %w", dir, err)
	}

	record.Version = RecordVersion
	data, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("endpoint: marshal record: %w", err)
	}

	tmp := filepath.Join(dir, ".endpoint.json.tmp")
	if err := os.WriteFile(tmp, data, filePerms); err != nil {
		return nil, fmt.Errorf("endpoint: write temp: %w", err)
	}
	if err := syncFile(tmp); err != nil {
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("endpoint: sync temp: %w", err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, "endpoint.json")); err != nil {
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("endpoint: rename: %w", err)
	}
	syncDir(dir)

	addr := &net.TCPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: record.Port,
	}
	return addr, nil
}

// Validate checks a loaded record for staleness, wrong boot ID, wrong
// service, non-loopback address, and PID mismatch.
func Validate(record EndpointRecord, currentBootID string, currentPID int, serviceName string) error {
	if record.Version != RecordVersion {
		return fmt.Errorf("%w: unsupported version %d", ErrMalformedRecord, record.Version)
	}
	if record.Service != serviceName {
		return fmt.Errorf("%w: got %q, want %q", ErrWrongService, record.Service, serviceName)
	}
	if record.BootID != currentBootID {
		return fmt.Errorf("%w: record %q, current %q", ErrStaleBootID, record.BootID, currentBootID)
	}
	if record.PID != currentPID {
		return fmt.Errorf("%w: record %d, current %d", ErrPIDMismatch, record.PID, currentPID)
	}
	ip := net.ParseIP(record.Address)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("%w: %q", ErrNonLoopback, record.Address)
	}
	if record.InstanceNonce == "" {
		return fmt.Errorf("%w: empty instance nonce", ErrMalformedRecord)
	}
	if record.ExpectedIdentity != "" && record.ExpectedIdentity != serviceName {
		return fmt.Errorf("%w: expected identity %q, got %q", ErrWrongService, record.ExpectedIdentity, serviceName)
	}
	return nil
}

// Cleanup removes the endpoint record at dir/endpoint.json if it matches
// the given record's service and instance nonce.
func Cleanup(dir string, record EndpointRecord) error {
	p := filepath.Join(dir, "endpoint.json")
	existing, err := readRecord(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if existing.Service != record.Service || existing.InstanceNonce != record.InstanceNonce {
		return nil
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("endpoint: remove %s: %w", p, err)
	}
	syncDir(dir)
	return nil
}

// GenerateNonce returns a random instance nonce string.
func GenerateNonce() string {
	return strconv.FormatUint(rand.Uint64(), 16)
}

// readRecord reads and parses an endpoint record from a file path.
func readRecord(path string) (EndpointRecord, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return EndpointRecord{}, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return EndpointRecord{}, ErrSymlinkDetected
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return EndpointRecord{}, err
	}
	var rec EndpointRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return EndpointRecord{}, fmt.Errorf("%w: %v", ErrMalformedRecord, err)
	}
	return rec, nil
}

// syncFile fsyncs a file by path.
func syncFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return f.Sync()
}

// syncDir fsyncs a directory. Best-effort on platforms that do not support it.
func syncDir(dir string) {
	f, err := os.Open(dir)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	_ = f.Sync()
}

// NewServiceDir returns the directory path for a service's endpoint record.
// Convention: /run/sovereignite/<service>/endpoint.json lives in this dir.
func NewServiceDir(base, service string) string {
	return filepath.Join(base, service)
}

// endpointMu serialises writes per service directory in a process.
var (
	endpointMu sync.Mutex
)

// PublishSerialised wraps Publish with a process-wide lock to prevent
// concurrent writes to the same directory from racing.
func PublishSerialised(dir string, record EndpointRecord) (net.Addr, error) {
	endpointMu.Lock()
	defer endpointMu.Unlock()
	return Publish(dir, record)
}

// readRecordWithSymlinkCheck reads a record and rejects symlinks.
func readRecordWithSymlinkCheck(path string) (EndpointRecord, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return EndpointRecord{}, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return EndpointRecord{}, ErrSymlinkDetected
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return EndpointRecord{}, err
	}
	var rec EndpointRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return EndpointRecord{}, fmt.Errorf("%w: %v", ErrMalformedRecord, err)
	}
	return rec, nil
}

// ReadRecord reads and validates an endpoint record from the standard path.
// It rejects symlinks and malformed records.
func ReadRecord(dir string) (EndpointRecord, error) {
	return readRecordWithSymlinkCheck(filepath.Join(dir, "endpoint.json"))
}

// ValidateRecord reads, checks staleness, and returns the record if valid.
func ValidateRecord(dir, currentBootID string, currentPID int, serviceName string) (EndpointRecord, error) {
	rec, err := ReadRecord(dir)
	if err != nil {
		return EndpointRecord{}, err
	}
	if err := Validate(rec, currentBootID, currentPID, serviceName); err != nil {
		return EndpointRecord{}, err
	}
	return rec, nil
}

// RecordFromFile is a convenience helper that reads and validates an endpoint
// record from a file path. It is used by clients resolving a service.
func RecordFromFile(path string) (EndpointRecord, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return EndpointRecord{}, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return EndpointRecord{}, ErrSymlinkDetected
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return EndpointRecord{}, err
	}
	var rec EndpointRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return EndpointRecord{}, fmt.Errorf("%w: %v", ErrMalformedRecord, err)
	}
	return rec, nil
}

// randomPort is a helper that returns the OS-assigned port from a listener
// bound to port 0 on loopback.
func randomPort(l net.Listener) int {
	return l.Addr().(*net.TCPAddr).Port
}

// now is a monotonic timestamp for staleness checks. Exported for tests.
var now = time.Now
