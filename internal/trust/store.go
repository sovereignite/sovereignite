// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package trust

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

const (
	maximumStateBytes  = 4 << 20
	maximumAnchorBytes = 512
	anchorVersion      = 1
)

type revisionAnchor struct {
	Version     int    `json:"version"`
	Revision    uint64 `json:"revision"`
	StateSHA256 string `json:"state_sha256,omitempty"`
}

// Store provides revision-checked atomic persistence. Implementations must
// reject a stale expected revision instead of overwriting a concurrent writer.
type Store interface {
	Load() (Snapshot, error)
	Commit(expectedRevision uint64, next Snapshot) error
}

// FileStore persists one owner-only, bounded JSON snapshot and a monotonic
// digest/revision anchor using same-directory temporary files, fsync, atomic
// rename, and directory fsync. An advisory lock plus revision comparison
// serializes cooperating processes. The anchor detects restoration of an older
// state file; deployment storage must independently protect whole-directory
// rollback.
type FileStore struct {
	mu         sync.Mutex
	path       string
	lockPath   string
	anchorPath string
}

// NewFileStore constructs a durable trust store at an absolute or resolvable
// path. No state is read or written until Load or Commit.
func NewFileStore(path string) (*FileStore, error) {
	if path == "" {
		return nil, errors.New("trust state path is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve trust state path: %w", err)
	}
	absolute = filepath.Clean(absolute)
	if filepath.Base(absolute) == "." ||
		filepath.Base(absolute) == string(filepath.Separator) {
		return nil, errors.New("trust state path must name a file")
	}
	return &FileStore{
		path:       absolute,
		lockPath:   absolute + ".lock",
		anchorPath: absolute + ".anchor",
	}, nil
}

// Load returns a validated deep copy. A missing state file is the canonical
// revision-zero state; an unknown version is never rewritten.
func (s *FileStore) Load() (Snapshot, error) {
	if s == nil || s.path == "" {
		return Snapshot{}, errors.New("trust state store is not configured")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	lock, err := s.acquireLock()
	if err != nil {
		return Snapshot{}, err
	}
	defer releaseFileLock(lock)
	return s.readLocked()
}

// Commit atomically replaces the complete snapshot only when the durable
// revision equals expectedRevision and next advances it by exactly one.
func (s *FileStore) Commit(expectedRevision uint64, next Snapshot) error {
	if s == nil || s.path == "" {
		return errors.New("trust state store is not configured")
	}
	if expectedRevision == ^uint64(0) ||
		next.Revision != expectedRevision+1 {
		return errors.New("trust state commit must advance the revision by one")
	}
	if err := validateSnapshot(next); err != nil {
		return fmt.Errorf("validate next trust state: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	lock, err := s.acquireLock()
	if err != nil {
		return err
	}
	defer releaseFileLock(lock)

	current, err := s.readLocked()
	if err != nil {
		return err
	}
	if current.Revision != expectedRevision {
		return fmt.Errorf(
			"%w: durable revision is %d, expected %d",
			ErrRevisionConflict,
			current.Revision,
			expectedRevision,
		)
	}
	encoded, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return fmt.Errorf("encode trust state: %w", err)
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maximumStateBytes {
		return fmt.Errorf(
			"encoded trust state is %d bytes, limit is %d",
			len(encoded),
			maximumStateBytes,
		)
	}
	if _, err := secureStateFile(s.path); err != nil &&
		!errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := atomicReplaceAndSync(s.path, encoded); err != nil {
		return err
	}
	return s.writeAnchorLocked(revisionAnchor{
		Version:     anchorVersion,
		Revision:    next.Revision,
		StateSHA256: stateDigest(encoded),
	})
}

func (s *FileStore) readLocked() (Snapshot, error) {
	info, err := secureStateFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		anchor, anchorErr := s.readAnchorLocked()
		switch {
		case errors.Is(anchorErr, os.ErrNotExist):
			if err := s.writeAnchorLocked(revisionAnchor{
				Version: anchorVersion,
			}); err != nil {
				return Snapshot{}, err
			}
		case anchorErr != nil:
			return Snapshot{}, anchorErr
		case anchor.Revision != 0 || anchor.StateSHA256 != "":
			return Snapshot{}, ErrStateRollback
		}
		return emptySnapshot(), nil
	}
	if err != nil {
		return Snapshot{}, err
	}
	if info.Size() <= 0 || info.Size() > maximumStateBytes {
		return Snapshot{}, errors.New("trust state has an invalid size")
	}
	file, err := os.Open(s.path)
	if err != nil {
		return Snapshot{}, fmt.Errorf("open trust state: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()
	opened, err := file.Stat()
	if err != nil {
		return Snapshot{}, fmt.Errorf("inspect opened trust state: %w", err)
	}
	if !os.SameFile(info, opened) ||
		!opened.Mode().IsRegular() ||
		opened.Mode().Perm() != 0o600 {
		return Snapshot{}, errors.New("trust state changed while opening")
	}

	encoded, err := io.ReadAll(io.LimitReader(file, maximumStateBytes+1))
	if err != nil {
		return Snapshot{}, fmt.Errorf("read trust state: %w", err)
	}
	if len(encoded) == 0 || len(encoded) > maximumStateBytes {
		return Snapshot{}, errors.New("trust state has an invalid size")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var snapshot Snapshot
	if err := decoder.Decode(&snapshot); err != nil {
		return Snapshot{}, fmt.Errorf("decode trust state: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return Snapshot{}, errors.New("trust state contains multiple JSON values")
		}
		return Snapshot{}, fmt.Errorf("decode trailing trust state: %w", err)
	}
	if err := validateSnapshot(snapshot); err != nil {
		return Snapshot{}, err
	}
	anchor, err := s.readAnchorLocked()
	if errors.Is(err, os.ErrNotExist) {
		return Snapshot{}, fmt.Errorf("%w: revision anchor is missing", ErrStateRollback)
	}
	if err != nil {
		return Snapshot{}, err
	}
	digest := stateDigest(encoded)
	switch {
	case snapshot.Revision < anchor.Revision:
		return Snapshot{}, fmt.Errorf(
			"%w: state revision %d predates anchor revision %d",
			ErrStateRollback,
			snapshot.Revision,
			anchor.Revision,
		)
	case snapshot.Revision == anchor.Revision:
		if digest != anchor.StateSHA256 {
			return Snapshot{}, fmt.Errorf(
				"%w: state digest differs from revision anchor",
				ErrStateRollback,
			)
		}
	case snapshot.Revision != anchor.Revision+1:
		return Snapshot{}, fmt.Errorf(
			"%w: state revision %d is not the single recoverable successor of anchor revision %d",
			ErrStateRollback,
			snapshot.Revision,
			anchor.Revision,
		)
	default:
		if err := s.writeAnchorLocked(revisionAnchor{
			Version:     anchorVersion,
			Revision:    snapshot.Revision,
			StateSHA256: digest,
		}); err != nil {
			return Snapshot{}, fmt.Errorf("repair trust state revision anchor: %w", err)
		}
	}
	return cloneSnapshot(snapshot), nil
}

func (s *FileStore) readAnchorLocked() (revisionAnchor, error) {
	info, err := secureOwnerOnlyFile(s.anchorPath, "trust state revision anchor")
	if err != nil {
		return revisionAnchor{}, err
	}
	if info.Size() <= 0 || info.Size() > maximumAnchorBytes {
		return revisionAnchor{}, errors.New("trust state revision anchor has an invalid size")
	}
	file, err := os.Open(s.anchorPath)
	if err != nil {
		return revisionAnchor{}, fmt.Errorf("open trust state revision anchor: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()
	opened, err := file.Stat()
	if err != nil {
		return revisionAnchor{}, fmt.Errorf("inspect opened trust state revision anchor: %w", err)
	}
	if !os.SameFile(info, opened) ||
		!opened.Mode().IsRegular() ||
		opened.Mode().Perm() != 0o600 {
		return revisionAnchor{}, errors.New(
			"trust state revision anchor changed while opening",
		)
	}
	decoder := json.NewDecoder(io.LimitReader(file, maximumAnchorBytes+1))
	decoder.DisallowUnknownFields()
	var anchor revisionAnchor
	if err := decoder.Decode(&anchor); err != nil {
		return revisionAnchor{}, fmt.Errorf("decode trust state revision anchor: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return revisionAnchor{}, errors.New(
				"trust state revision anchor contains multiple JSON values",
			)
		}
		return revisionAnchor{}, fmt.Errorf(
			"decode trailing trust state revision anchor: %w",
			err,
		)
	}
	if anchor.Version != anchorVersion {
		return revisionAnchor{}, errors.New("trust state revision anchor version is unsupported")
	}
	if anchor.Revision == 0 {
		if anchor.StateSHA256 != "" {
			return revisionAnchor{}, errors.New(
				"revision-zero trust state anchor has a digest",
			)
		}
	} else if !certificateIDPattern.MatchString(anchor.StateSHA256) {
		return revisionAnchor{}, errors.New("trust state revision anchor digest is invalid")
	}
	return anchor, nil
}

func (s *FileStore) writeAnchorLocked(anchor revisionAnchor) error {
	if anchor.Version != anchorVersion ||
		(anchor.Revision == 0 && anchor.StateSHA256 != "") ||
		(anchor.Revision != 0 && !certificateIDPattern.MatchString(anchor.StateSHA256)) {
		return errors.New("trust state revision anchor is invalid")
	}
	if existing, err := s.readAnchorLocked(); err == nil {
		if anchor.Revision < existing.Revision {
			return ErrStateRollback
		}
		if existing.Revision != ^uint64(0) &&
			anchor.Revision > existing.Revision+1 {
			return ErrStateRollback
		}
		if anchor.Revision == existing.Revision &&
			anchor.StateSHA256 != existing.StateSHA256 {
			return ErrStateRollback
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	encoded, err := json.MarshalIndent(anchor, "", "  ")
	if err != nil {
		return fmt.Errorf("encode trust state revision anchor: %w", err)
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maximumAnchorBytes {
		return errors.New("encoded trust state revision anchor exceeds its size limit")
	}
	if _, err := secureOwnerOnlyFile(
		s.anchorPath,
		"trust state revision anchor",
	); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return atomicReplaceAndSync(s.anchorPath, encoded)
}

func stateDigest(encoded []byte) string {
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func (s *FileStore) acquireLock() (*os.File, error) {
	directory := filepath.Dir(s.path)
	if err := ensureTrustDirectory(directory); err != nil {
		return nil, err
	}
	before, beforeErr := os.Lstat(s.lockPath)
	if beforeErr != nil && !errors.Is(beforeErr, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect trust state lock: %w", beforeErr)
	}
	if beforeErr == nil {
		if before.Mode()&os.ModeSymlink != 0 ||
			!before.Mode().IsRegular() ||
			before.Mode().Perm() != 0o600 {
			return nil, errors.New("trust state lock is not an owner-only regular file")
		}
	}
	lock, err := os.OpenFile(s.lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open trust state lock: %w", err)
	}
	opened, err := lock.Stat()
	if err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("inspect opened trust state lock: %w", err)
	}
	after, err := os.Lstat(s.lockPath)
	if err != nil ||
		after.Mode()&os.ModeSymlink != 0 ||
		!after.Mode().IsRegular() ||
		after.Mode().Perm() != 0o600 ||
		!os.SameFile(opened, after) ||
		(beforeErr == nil && !os.SameFile(before, opened)) {
		_ = lock.Close()
		return nil, errors.New("trust state lock changed while opening")
	}
	if err := requireEffectiveOwner(s.lockPath, opened); err != nil {
		_ = lock.Close()
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("lock trust state: %w", err)
	}
	return lock, nil
}

func releaseFileLock(lock *os.File) {
	if lock == nil {
		return
	}
	_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	_ = lock.Close()
}

func ensureTrustDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return fmt.Errorf("create trust state directory: %w", err)
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return fmt.Errorf("inspect trust state directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 ||
		!info.IsDir() ||
		info.Mode().Perm() != 0o700 {
		return errors.New("trust state directory must be a real owner-only directory")
	}
	return requireEffectiveOwner(path, info)
}

func secureStateFile(path string) (os.FileInfo, error) {
	return secureOwnerOnlyFile(path, "trust state")
}

func secureOwnerOnlyFile(path, description string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 ||
		!info.Mode().IsRegular() ||
		info.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("%s is not an owner-only regular file", description)
	}
	if err := requireEffectiveOwner(path, info); err != nil {
		return nil, err
	}
	return info, nil
}

func requireEffectiveOwner(path string, info os.FileInfo) error {
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok || status == nil {
		return fmt.Errorf("ownership metadata is unavailable for %q", path)
	}
	if status.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf(
			"trust state path %q is owned by uid %d, want %d",
			path,
			status.Uid,
			os.Geteuid(),
		)
	}
	return nil
}

func atomicReplaceAndSync(path string, encoded []byte) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create trust state temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("set trust state permissions: %w", err)
	}
	if _, err := io.Copy(temporary, bytes.NewReader(encoded)); err != nil {
		return fmt.Errorf("write trust state: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync trust state: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close trust state: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace trust state: %w", err)
	}
	directoryFile, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open trust state directory for sync: %w", err)
	}
	syncErr := directoryFile.Sync()
	closeErr := directoryFile.Close()
	if syncErr != nil {
		return fmt.Errorf("sync trust state directory: %w", syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close trust state directory: %w", closeErr)
	}
	return nil
}
