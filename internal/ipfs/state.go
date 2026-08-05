// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package ipfs

import (
	"bytes"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/ipfs/go-cid"
)

const (
	// PublicationStateVersion is the only durable publication-state schema
	// understood by this implementation.
	PublicationStateVersion = 2

	maximumPublicationStateBytes = 2 << 20
)

var (
	// ErrPublicationStateConflict means another writer committed a newer
	// durable revision.
	ErrPublicationStateConflict = errors.New(
		"IPFS publication state revision conflict",
	)
	// ErrPublicationStateDurabilityUncertain means an atomic replacement was
	// visible but its containing-directory durability barrier failed.
	ErrPublicationStateDurabilityUncertain = errors.New(
		"IPFS publication state durability is uncertain",
	)
)

// PendingPublication is persisted before network publication. Its exact
// public signed record is replayed after a crash, so a sequence can never be
// reused for different content.
type PendingPublication struct {
	PublicationID string       `json:"publication_id"`
	Digest        string       `json:"digest"`
	TrustRevision uint64       `json:"trust_revision"`
	RootCID       string       `json:"root_cid"`
	Record        SignedRecord `json:"record"`
}

// Clone returns a deep copy.
func (p PendingPublication) Clone() PendingPublication {
	p.Record = p.Record.Clone()
	return p
}

// PublicationState is public-only durable IPNS publication metadata.
// HighSequence is the highest sequence ever durably issued, including a
// pending record whose network result may be unknown.
type PublicationState struct {
	Version           int                 `json:"version"`
	Revision          uint64              `json:"revision"`
	IPNSName          string              `json:"ipns_name,omitempty"`
	HighSequence      uint64              `json:"high_sequence"`
	LastSequence      uint64              `json:"last_sequence"`
	LastPublicationID string              `json:"last_publication_id,omitempty"`
	LastDigest        string              `json:"last_digest,omitempty"`
	LastTrustRevision uint64              `json:"last_trust_revision,omitempty"`
	LastRootCID       string              `json:"last_root_cid,omitempty"`
	LastRecord        *SignedRecord       `json:"last_record,omitempty"`
	Pending           *PendingPublication `json:"pending,omitempty"`
}

// Clone returns a deep copy.
func (s PublicationState) Clone() PublicationState {
	if s.LastRecord != nil {
		record := s.LastRecord.Clone()
		s.LastRecord = &record
	}
	if s.Pending != nil {
		pending := s.Pending.Clone()
		s.Pending = &pending
	}
	return s
}

// PublicationStateStore atomically persists complete public publication
// state with revision comparison.
type PublicationStateStore interface {
	Load() (PublicationState, error)
	Commit(expectedRevision uint64, next PublicationState) error
}

// FilePublicationStateStore stores publication metadata inside the persistent
// Kubo repository. The repository must already exist as a real owner-only
// directory; systemd StateDirectory creates it in production.
type FilePublicationStateStore struct {
	mu             sync.Mutex
	repositoryPath string
}

// NewFilePublicationStateStore creates a bounded store without creating or
// modifying the Kubo repository.
func NewFilePublicationStateStore(
	repositoryPath string,
) (*FilePublicationStateStore, error) {
	if err := validateServiceRoot(repositoryPath); err != nil {
		return nil, fmt.Errorf("publication repository: %w", err)
	}
	return &FilePublicationStateStore{
		repositoryPath: filepath.Clean(repositoryPath),
	}, nil
}

// Load returns a validated copy. Missing state is the current schema at revision
// zero; an unknown version is never rewritten.
func (s *FilePublicationStateStore) Load() (PublicationState, error) {
	if s == nil || s.repositoryPath == "" {
		return PublicationState{}, errors.New(
			"IPFS publication state store is not configured",
		)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	root, err := openSecureDirectory(s.repositoryPath)
	if err != nil {
		return PublicationState{}, err
	}
	defer func() {
		_ = root.Close()
	}()
	lock, err := acquirePublicationLock(root)
	if err != nil {
		return PublicationState{}, err
	}
	defer releasePublicationLock(lock)
	state, err := readPublicationState(root)
	if err != nil {
		return PublicationState{}, err
	}
	if err := requireDirectoryStillAtPath(root, s.repositoryPath); err != nil {
		return PublicationState{}, err
	}
	return state.Clone(), nil
}

// Commit durably replaces the complete state only when its revision advances
// by exactly one from the currently durable revision.
func (s *FilePublicationStateStore) Commit(
	expectedRevision uint64,
	next PublicationState,
) error {
	if s == nil || s.repositoryPath == "" {
		return errors.New("IPFS publication state store is not configured")
	}
	if expectedRevision == math.MaxUint64 ||
		next.Revision != expectedRevision+1 {
		return errors.New(
			"IPFS publication state commit must advance revision by one",
		)
	}
	if err := validatePublicationState(next); err != nil {
		return fmt.Errorf("validate next IPFS publication state: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	root, err := openSecureDirectory(s.repositoryPath)
	if err != nil {
		return err
	}
	defer func() {
		_ = root.Close()
	}()
	lock, err := acquirePublicationLock(root)
	if err != nil {
		return err
	}
	defer releasePublicationLock(lock)
	current, err := readPublicationState(root)
	if err != nil {
		return err
	}
	if current.Revision != expectedRevision {
		return fmt.Errorf(
			"%w: durable revision is %d, expected %d",
			ErrPublicationStateConflict,
			current.Revision,
			expectedRevision,
		)
	}
	encoded, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return fmt.Errorf("encode IPFS publication state: %w", err)
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maximumPublicationStateBytes {
		return errors.New("encoded IPFS publication state exceeds 2 MiB")
	}
	if err := validateOptionalRegularFile(
		root,
		publicationStateFilename,
	); err != nil {
		return err
	}
	if err := atomicReplaceInRoot(
		root,
		publicationStateFilename,
		encoded,
	); err != nil {
		return err
	}
	return requireDirectoryStillAtPath(root, s.repositoryPath)
}

func emptyPublicationState() PublicationState {
	return PublicationState{Version: PublicationStateVersion}
}

func validatePublicationState(state PublicationState) error {
	if state.Version != PublicationStateVersion {
		return fmt.Errorf(
			"unsupported IPFS publication state version %d",
			state.Version,
		)
	}
	if state.LastSequence > state.HighSequence {
		return errors.New(
			"last published sequence exceeds the durable high-water mark",
		)
	}
	if state.Revision == 0 &&
		(state.IPNSName != "" ||
			state.HighSequence != 0 ||
			state.LastSequence != 0 ||
			state.LastTrustRevision != 0 ||
			state.Pending != nil) {
		return errors.New(
			"revision-zero publication state contains committed metadata",
		)
	}
	if state.IPNSName != "" {
		if err := validateCanonicalIPNSName(state.IPNSName); err != nil {
			return err
		}
	}
	if state.LastSequence == 0 {
		if state.LastPublicationID != "" ||
			state.LastDigest != "" ||
			state.LastTrustRevision != 0 ||
			state.LastRootCID != "" ||
			state.LastRecord != nil {
			return errors.New(
				"completed publication metadata exists without a sequence",
			)
		}
	} else {
		if state.IPNSName == "" ||
			!isLowerHexDigest(state.LastPublicationID) ||
			state.LastDigest != state.LastPublicationID ||
			state.LastTrustRevision == 0 {
			return errors.New("completed publication identity is invalid")
		}
		root, err := canonicalRootCID(state.LastRootCID)
		if err != nil {
			return err
		}
		if state.LastRecord == nil {
			return errors.New("completed publication record is missing")
		}
		recordRoot, err := state.LastRecord.RootCID()
		if err != nil ||
			state.LastRecord.Sequence != state.LastSequence ||
			state.LastRecord.Name != state.IPNSName ||
			!recordRoot.Equals(root) {
			return errors.New(
				"completed publication record does not match state",
			)
		}
		if _, err := state.LastRecord.unsignedPayload(); err != nil {
			return err
		}
		if len(state.LastRecord.Signature) == 0 {
			return errors.New("completed publication signature is missing")
		}
	}
	if state.Pending == nil {
		if state.HighSequence != state.LastSequence {
			return errors.New(
				"unused sequence exists without a pending publication",
			)
		}
		return nil
	}
	pending := state.Pending
	if state.IPNSName == "" ||
		!isLowerHexDigest(pending.PublicationID) ||
		pending.Digest != pending.PublicationID ||
		pending.TrustRevision == 0 ||
		pending.TrustRevision <= state.LastTrustRevision {
		return errors.New("pending publication identity is invalid")
	}
	root, err := canonicalRootCID(pending.RootCID)
	if err != nil {
		return err
	}
	recordRoot, err := pending.Record.RootCID()
	if err != nil ||
		pending.Record.Name != state.IPNSName ||
		pending.Record.Sequence != state.HighSequence ||
		pending.Record.Sequence <= state.LastSequence ||
		!recordRoot.Equals(root) {
		return errors.New("pending publication record does not match state")
	}
	if _, err := pending.Record.unsignedPayload(); err != nil {
		return err
	}
	if len(pending.Record.Signature) == 0 {
		return errors.New("pending publication signature is missing")
	}
	return nil
}

func canonicalRootCID(encoded string) (cid.Cid, error) {
	root, err := cid.Decode(encoded)
	if err != nil ||
		!root.Defined() ||
		root.Version() != 1 ||
		root.String() != encoded {
		return cid.Undef, errors.New("publication root is not a canonical CIDv1")
	}
	return root, nil
}

func readPublicationState(root *os.Root) (PublicationState, error) {
	info, err := root.Lstat(publicationStateFilename)
	if errors.Is(err, os.ErrNotExist) {
		return emptyPublicationState(), nil
	}
	if err != nil {
		return PublicationState{}, fmt.Errorf(
			"inspect IPFS publication state: %w",
			err,
		)
	}
	if err := validateOwnedRegularFile(
		publicationStateFilename,
		info,
	); err != nil {
		return PublicationState{}, err
	}
	if info.Size() <= 0 || info.Size() > maximumPublicationStateBytes {
		return PublicationState{}, errors.New(
			"IPFS publication state has an invalid size",
		)
	}
	file, err := root.Open(publicationStateFilename)
	if err != nil {
		return PublicationState{}, fmt.Errorf(
			"open IPFS publication state: %w",
			err,
		)
	}
	defer func() {
		_ = file.Close()
	}()
	opened, err := file.Stat()
	if err != nil {
		return PublicationState{}, fmt.Errorf(
			"inspect opened IPFS publication state: %w",
			err,
		)
	}
	after, err := root.Lstat(publicationStateFilename)
	if err != nil ||
		!os.SameFile(info, opened) ||
		!os.SameFile(opened, after) {
		return PublicationState{}, errors.New(
			"IPFS publication state changed while opening",
		)
	}
	decoder := json.NewDecoder(
		io.LimitReader(file, maximumPublicationStateBytes+1),
	)
	decoder.DisallowUnknownFields()
	var state PublicationState
	if err := decoder.Decode(&state); err != nil {
		return PublicationState{}, fmt.Errorf(
			"decode IPFS publication state: %w",
			err,
		)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return PublicationState{}, errors.New(
				"IPFS publication state contains multiple JSON values",
			)
		}
		return PublicationState{}, fmt.Errorf(
			"decode trailing IPFS publication state: %w",
			err,
		)
	}
	if err := validatePublicationState(state); err != nil {
		return PublicationState{}, err
	}
	return state.Clone(), nil
}

func openSecureDirectory(path string) (*os.Root, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect secure directory %q: %w", path, err)
	}
	if before.Mode()&os.ModeSymlink != 0 ||
		!before.IsDir() ||
		before.Mode().Perm() != 0o700 {
		return nil, fmt.Errorf(
			"secure directory %q must be a real owner-only directory",
			path,
		)
	}
	if err := requireEffectiveOwner(path, before); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, fmt.Errorf("open secure directory %q: %w", path, err)
	}
	anchored, err := root.Stat(".")
	if err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("inspect anchored directory %q: %w", path, err)
	}
	after, err := os.Lstat(path)
	if err != nil ||
		!os.SameFile(before, anchored) ||
		!os.SameFile(anchored, after) {
		_ = root.Close()
		return nil, fmt.Errorf("secure directory %q changed while opening", path)
	}
	return root, nil
}

func requireDirectoryStillAtPath(root *os.Root, path string) error {
	anchored, err := root.Stat(".")
	if err != nil {
		return fmt.Errorf("inspect anchored directory %q: %w", path, err)
	}
	current, err := os.Lstat(path)
	if err != nil ||
		current.Mode()&os.ModeSymlink != 0 ||
		!current.IsDir() ||
		current.Mode().Perm() != 0o700 ||
		!os.SameFile(anchored, current) {
		return fmt.Errorf("secure directory %q changed during operation", path)
	}
	return requireEffectiveOwner(path, current)
}

func acquirePublicationLock(root *os.Root) (*os.File, error) {
	if err := validateOptionalRegularFile(
		root,
		publicationLockFilename,
	); err != nil {
		return nil, err
	}
	lock, err := root.OpenFile(
		publicationLockFilename,
		os.O_CREATE|os.O_RDWR,
		0o600,
	)
	if err != nil {
		return nil, fmt.Errorf("open IPFS publication lock: %w", err)
	}
	opened, err := lock.Stat()
	if err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("inspect IPFS publication lock: %w", err)
	}
	pathInfo, err := root.Lstat(publicationLockFilename)
	if err != nil ||
		!os.SameFile(opened, pathInfo) {
		_ = lock.Close()
		return nil, errors.New("IPFS publication lock changed while opening")
	}
	if err := validateOwnedRegularFile(
		publicationLockFilename,
		opened,
	); err != nil {
		_ = lock.Close()
		return nil, err
	}
	if err := flock(lock, syscall.LOCK_EX); err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("lock IPFS publication state: %w", err)
	}
	return lock, nil
}

func releasePublicationLock(lock *os.File) {
	if lock == nil {
		return
	}
	_ = flock(lock, syscall.LOCK_UN)
	_ = lock.Close()
}

func flock(file *os.File, operation int) error {
	for {
		err := syscall.Flock(int(file.Fd()), operation)
		if !errors.Is(err, syscall.EINTR) {
			return err
		}
	}
}

func validateOptionalRegularFile(root *os.Root, name string) error {
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect %s: %w", name, err)
	}
	return validateOwnedRegularFile(name, info)
}

func validateOwnedRegularFile(name string, info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 ||
		!info.Mode().IsRegular() ||
		info.Mode().Perm() != 0o600 {
		return fmt.Errorf("%s must be an owner-only regular file", name)
	}
	return requireEffectiveOwner(name, info)
}

func requireEffectiveOwner(path string, info os.FileInfo) error {
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok || status == nil {
		return fmt.Errorf("ownership metadata is unavailable for %q", path)
	}
	if status.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf(
			"path %q is owned by uid %d, want %d",
			path,
			status.Uid,
			os.Geteuid(),
		)
	}
	return nil
}

func atomicReplaceInRoot(root *os.Root, name string, content []byte) error {
	temporaryName, err := temporaryFilename(name)
	if err != nil {
		return err
	}
	temporary, err := root.OpenFile(
		temporaryName,
		os.O_WRONLY|os.O_CREATE|os.O_EXCL,
		0o600,
	)
	if err != nil {
		return fmt.Errorf("create IPFS publication state temporary: %w", err)
	}
	renamed := false
	defer func() {
		_ = temporary.Close()
		if !renamed {
			_ = root.Remove(temporaryName)
		}
	}()
	if _, err := io.Copy(temporary, bytes.NewReader(content)); err != nil {
		return fmt.Errorf("write IPFS publication state temporary: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync IPFS publication state temporary: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close IPFS publication state temporary: %w", err)
	}
	if err := root.Rename(temporaryName, name); err != nil {
		return fmt.Errorf("replace IPFS publication state: %w", err)
	}
	renamed = true
	directory, err := root.Open(".")
	if err != nil {
		return fmt.Errorf(
			"%w: open repository for sync: %v",
			ErrPublicationStateDurabilityUncertain,
			err,
		)
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil || closeErr != nil {
		return fmt.Errorf(
			"%w: sync=%v close=%v",
			ErrPublicationStateDurabilityUncertain,
			syncErr,
			closeErr,
		)
	}
	return nil
}

func temporaryFilename(target string) (string, error) {
	random := make([]byte, 16)
	if _, err := cryptorand.Read(random); err != nil {
		return "", fmt.Errorf(
			"generate IPFS publication state temporary name: %w",
			err,
		)
	}
	return "." + target + ".tmp-" + hex.EncodeToString(random), nil
}
