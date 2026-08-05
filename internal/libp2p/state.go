// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package libp2p

import (
	"bytes"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
)

const (
	identityStateVersion = 1
	maxIdentityStateSize = 64 * 1024
)

var (
	// ErrIdentityMismatch means the injected TPM handle or public identity no
	// longer matches the lifetime-stable state.
	ErrIdentityMismatch = errors.New("persisted identity does not match TPM key")
	// ErrUnsupportedIdentityVersion means the state was written by an
	// unsupported schema version.
	ErrUnsupportedIdentityVersion = errors.New("unsupported identity state version")
)

type identityRecord struct {
	Version   int    `json:"version"`
	TPMHandle string `json:"tpm_handle"`
	PublicKey string `json:"public_key"`
	PeerID    string `json:"peer_id"`
	Name      string `json:"name"`
}

func newIdentityRecord(identity PublicIdentity) (identityRecord, error) {
	publicKey, err := libp2pcrypto.MarshalPublicKey(identity.PublicKey)
	if err != nil {
		return identityRecord{}, fmt.Errorf("marshal public identity: %w", err)
	}
	return identityRecord{
		Version:   identityStateVersion,
		TPMHandle: fmt.Sprintf("0x%08x", identity.TPMHandle),
		PublicKey: base64.StdEncoding.EncodeToString(publicKey),
		PeerID:    identity.PeerID.String(),
		Name:      identity.Name,
	}, nil
}

func ensureIdentityState(
	config Config,
	expected identityRecord,
) (returnErr error) {
	stateRoot := filepath.Clean(config.StateRoot)
	root, err := openPrivateDirectory(stateRoot)
	if err != nil {
		return fmt.Errorf("create identity state root: %w", err)
	}
	defer func() {
		returnErr = errors.Join(
			returnErr,
			requireRootStillAtPath(root, stateRoot),
			root.Close(),
		)
	}()
	persisted, err := readIdentityRecord(root, identityStateFilename)
	switch {
	case err == nil:
		return compareIdentityRecords(persisted, expected)
	case !errors.Is(err, os.ErrNotExist):
		return err
	}

	encoded, err := json.MarshalIndent(expected, "", "  ")
	if err != nil {
		return fmt.Errorf("encode identity state: %w", err)
	}
	encoded = append(encoded, '\n')
	created, err := atomicCreate(
		root,
		identityStateFilename,
		encoded,
		0o600,
	)
	if err != nil {
		return fmt.Errorf("persist identity state: %w", err)
	}
	if created {
		return nil
	}
	persisted, err = readIdentityRecord(root, identityStateFilename)
	if err != nil {
		return err
	}
	return compareIdentityRecords(persisted, expected)
}

func openPrivateDirectory(path string) (*os.Root, error) {
	cleaned := filepath.Clean(path)
	volume := filepath.VolumeName(cleaned)
	filesystemRoot := volume + string(filepath.Separator)
	if volume == "" {
		filesystemRoot = string(filepath.Separator)
	}
	remainder := strings.TrimPrefix(cleaned, filesystemRoot)
	components := strings.Split(remainder, string(filepath.Separator))
	root, err := os.OpenRoot(filesystemRoot)
	if err != nil {
		return nil, fmt.Errorf("open filesystem root: %w", err)
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = root.Close()
		}
	}()
	rootInfo, err := root.Stat(".")
	if err != nil {
		return nil, fmt.Errorf("inspect anchored filesystem root: %w", err)
	}
	if err := requireTrustedDirectoryOwner(filesystemRoot, rootInfo); err != nil {
		return nil, err
	}
	currentPath := filesystemRoot
	for _, component := range components {
		if component == "" {
			continue
		}
		currentPath = filepath.Join(currentPath, component)
		nextRoot, err := root.OpenRoot(component)
		if errors.Is(err, os.ErrNotExist) {
			parentInfo, statErr := root.Stat(".")
			if statErr != nil {
				return nil, fmt.Errorf(
					"inspect trusted parent for metadata path component %q: %w",
					currentPath,
					statErr,
				)
			}
			parentPath := filepath.Dir(currentPath)
			if trustErr := requireTrustedDirectoryOwner(
				parentPath,
				parentInfo,
			); trustErr != nil {
				return nil, trustErr
			}
			if mkdirErr := root.Mkdir(component, 0o700); mkdirErr != nil &&
				!errors.Is(mkdirErr, os.ErrExist) {
				return nil, fmt.Errorf(
					"create anchored metadata path component %q: %w",
					currentPath,
					mkdirErr,
				)
			}
			nextRoot, err = root.OpenRoot(component)
		}
		if err != nil {
			return nil, fmt.Errorf(
				"anchor metadata path component %q: %w",
				currentPath,
				err,
			)
		}
		anchoredInfo, err := nextRoot.Stat(".")
		if err != nil {
			_ = nextRoot.Close()
			return nil, fmt.Errorf(
				"inspect anchored metadata path component %q: %w",
				currentPath,
				err,
			)
		}
		pathInfo, err := root.Lstat(component)
		if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 ||
			!pathInfo.IsDir() || !os.SameFile(pathInfo, anchoredInfo) {
			_ = nextRoot.Close()
			if err != nil {
				return nil, fmt.Errorf(
					"reinspect metadata path component %q: %w",
					currentPath,
					err,
				)
			}
			return nil, fmt.Errorf(
				"metadata path component %q changed while anchoring",
				currentPath,
			)
		}
		if err := requireTrustedDirectoryOwner(
			currentPath,
			anchoredInfo,
		); err != nil {
			_ = nextRoot.Close()
			return nil, err
		}
		if err := root.Close(); err != nil {
			_ = nextRoot.Close()
			return nil, fmt.Errorf(
				"close parent of metadata path component %q: %w",
				currentPath,
				err,
			)
		}
		root = nextRoot
	}
	if err := requireRootStillAtPath(root, cleaned); err != nil {
		return nil, err
	}
	closeOnError = false
	return root, nil
}

func requireRootStillAtPath(root *os.Root, path string) error {
	anchoredInfo, err := root.Stat(".")
	if err != nil {
		return fmt.Errorf("inspect anchored metadata root: %w", err)
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("reinspect metadata root path: %w", err)
	}
	if !pathInfo.IsDir() || pathInfo.Mode()&os.ModeSymlink != 0 ||
		!anchoredInfo.IsDir() || !os.SameFile(pathInfo, anchoredInfo) {
		return errors.New("metadata root path no longer identifies its anchored directory")
	}
	if err := requireEffectiveUserOwner(path, anchoredInfo); err != nil {
		return err
	}
	if anchoredInfo.Mode().Perm() != 0o700 {
		return fmt.Errorf(
			"metadata root permissions are %o, want 700; refusing to change an existing directory",
			anchoredInfo.Mode().Perm(),
		)
	}
	return nil
}

func requireTrustedDirectoryOwner(path string, info os.FileInfo) error {
	owner, err := fileOwner(info)
	if err != nil {
		return fmt.Errorf("inspect metadata path owner %q: %w", path, err)
	}
	effectiveUser := uint32(os.Geteuid())
	if owner != 0 && owner != effectiveUser {
		return fmt.Errorf(
			"metadata path component %q is owned by untrusted uid %d",
			path,
			owner,
		)
	}
	if info.Mode().Perm()&0o022 != 0 &&
		(owner != 0 || info.Mode()&os.ModeSticky == 0) {
		return fmt.Errorf(
			"metadata path component %q is group- or world-writable",
			path,
		)
	}
	return nil
}

func requireEffectiveUserOwner(path string, info os.FileInfo) error {
	owner, err := fileOwner(info)
	if err != nil {
		return fmt.Errorf("inspect metadata owner %q: %w", path, err)
	}
	if owner != uint32(os.Geteuid()) {
		return fmt.Errorf(
			"metadata path %q is owned by uid %d, want effective uid %d",
			path,
			owner,
			os.Geteuid(),
		)
	}
	return nil
}

func fileOwner(info os.FileInfo) (uint32, error) {
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok || status == nil {
		return 0, errors.New("file ownership metadata is unavailable")
	}
	return status.Uid, nil
}

func readIdentityRecord(
	root *os.Root,
	name string,
) (identityRecord, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return identityRecord{}, err
	}
	if !info.Mode().IsRegular() {
		return identityRecord{}, errors.New("identity state is not a regular file")
	}
	if err := requireEffectiveUserOwner(name, info); err != nil {
		return identityRecord{}, err
	}
	if info.Mode().Perm() != 0o600 {
		return identityRecord{}, fmt.Errorf(
			"identity state permissions are %o, want 600",
			info.Mode().Perm(),
		)
	}
	if info.Size() <= 0 || info.Size() > maxIdentityStateSize {
		return identityRecord{}, errors.New("identity state has an invalid size")
	}
	file, err := root.Open(name)
	if err != nil {
		return identityRecord{}, fmt.Errorf("open identity state: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()
	openedInfo, err := file.Stat()
	if err != nil {
		return identityRecord{}, fmt.Errorf("inspect opened identity state: %w", err)
	}
	if !os.SameFile(info, openedInfo) {
		return identityRecord{}, errors.New("identity state changed while opening")
	}
	if err := requireEffectiveUserOwner(name, openedInfo); err != nil {
		return identityRecord{}, err
	}
	if !openedInfo.Mode().IsRegular() || openedInfo.Mode().Perm() != 0o600 {
		return identityRecord{}, errors.New("opened identity state is not an owner-only regular file")
	}
	if openedInfo.Size() <= 0 || openedInfo.Size() > maxIdentityStateSize {
		return identityRecord{}, errors.New("opened identity state has an invalid size")
	}

	decoder := json.NewDecoder(io.LimitReader(file, maxIdentityStateSize+1))
	decoder.DisallowUnknownFields()
	var record identityRecord
	if err := decoder.Decode(&record); err != nil {
		return identityRecord{}, fmt.Errorf("decode identity state: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return identityRecord{}, errors.New("identity state contains trailing data")
		}
		return identityRecord{}, fmt.Errorf("decode trailing identity state: %w", err)
	}
	if record.Version != identityStateVersion {
		return identityRecord{}, fmt.Errorf(
			"%w: %d",
			ErrUnsupportedIdentityVersion,
			record.Version,
		)
	}
	return record, nil
}

func compareIdentityRecords(persisted, expected identityRecord) error {
	if persisted.Version != expected.Version {
		return fmt.Errorf(
			"%w: %d",
			ErrUnsupportedIdentityVersion,
			persisted.Version,
		)
	}
	if persisted.TPMHandle != expected.TPMHandle {
		return fmt.Errorf("%w: TPM handle changed", ErrIdentityMismatch)
	}
	if persisted.PublicKey != expected.PublicKey {
		return fmt.Errorf("%w: public key changed", ErrIdentityMismatch)
	}
	if persisted.PeerID != expected.PeerID {
		return fmt.Errorf("%w: peer ID changed", ErrIdentityMismatch)
	}
	if persisted.Name != expected.Name {
		return fmt.Errorf("%w: canonical name changed", ErrIdentityMismatch)
	}
	return nil
}

func atomicCreate(
	root *os.Root,
	name string,
	content []byte,
	mode os.FileMode,
) (bool, error) {
	temporary, temporaryName, err := createTemporaryFile(root, ".identity-")
	if err != nil {
		return false, err
	}
	defer func() {
		_ = temporary.Close()
		_ = root.Remove(temporaryName)
	}()

	if err := temporary.Chmod(mode); err != nil {
		return false, err
	}
	if _, err := temporary.Write(content); err != nil {
		return false, err
	}
	if err := temporary.Sync(); err != nil {
		return false, err
	}
	if err := temporary.Close(); err != nil {
		return false, err
	}
	if err := root.Link(temporaryName, name); err != nil {
		if errors.Is(err, os.ErrExist) {
			return false, nil
		}
		return false, err
	}
	if err := syncRoot(root); err != nil {
		return false, err
	}
	if err := root.Remove(temporaryName); err != nil {
		return false, err
	}
	if err := syncRoot(root); err != nil {
		return false, err
	}
	return true, nil
}

func atomicReplace(
	root *os.Root,
	name string,
	content []byte,
	mode os.FileMode,
) error {
	_, err := atomicReplaceTracked(root, name, content, mode)
	return err
}

func atomicReplaceTracked(
	root *os.Root,
	name string,
	content []byte,
	mode os.FileMode,
) (os.FileInfo, error) {
	temporary, temporaryName, err := createTemporaryFile(root, ".endpoint-")
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = temporary.Close()
		_ = root.Remove(temporaryName)
	}()

	if err := temporary.Chmod(mode); err != nil {
		return nil, err
	}
	if _, err := temporary.Write(content); err != nil {
		return nil, err
	}
	if err := temporary.Sync(); err != nil {
		return nil, err
	}
	publishedInfo, err := temporary.Stat()
	if err != nil {
		return nil, err
	}
	if err := temporary.Close(); err != nil {
		return nil, err
	}
	if err := root.Rename(temporaryName, name); err != nil {
		return nil, err
	}
	if err := syncRoot(root); err != nil {
		return publishedInfo, err
	}
	return publishedInfo, nil
}

func removeIfOwnedFileMatches(
	root *os.Root,
	name string,
	expected []byte,
	expectedInfo os.FileInfo,
) error {
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if expectedInfo == nil || !os.SameFile(info, expectedInfo) {
		return nil
	}
	if !info.Mode().IsRegular() || info.Size() != int64(len(expected)) {
		return nil
	}
	file, err := root.Open(name)
	if err != nil {
		return err
	}
	defer func() {
		_ = file.Close()
	}()
	openedInfo, err := file.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(openedInfo, expectedInfo) {
		return nil
	}
	content, err := io.ReadAll(io.LimitReader(file, int64(len(expected))+1))
	if err != nil {
		return err
	}
	if !bytes.Equal(content, expected) {
		return nil
	}
	pathInfo, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !os.SameFile(pathInfo, openedInfo) {
		return nil
	}
	if err := root.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncRoot(root)
}

func requireOwnedRegularFile(
	root *os.Root,
	name string,
	expectedInfo os.FileInfo,
	mode os.FileMode,
	size int64,
) error {
	if expectedInfo == nil {
		return errors.New("expected file identity is required")
	}
	info, err := root.Lstat(name)
	if err != nil {
		return err
	}
	if !os.SameFile(info, expectedInfo) {
		return errors.New("published file was replaced")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != mode {
		return errors.New("published file is not an owner-only regular file")
	}
	if info.Size() != size {
		return errors.New("published file has an unexpected size")
	}
	return requireEffectiveUserOwner(name, info)
}

func createTemporaryFile(
	root *os.Root,
	prefix string,
) (*os.File, string, error) {
	for attempt := 0; attempt < 128; attempt++ {
		random := make([]byte, 16)
		if _, err := cryptorand.Read(random); err != nil {
			return nil, "", fmt.Errorf("generate temporary filename: %w", err)
		}
		name := prefix + hex.EncodeToString(random)
		file, err := root.OpenFile(
			name,
			os.O_CREATE|os.O_EXCL|os.O_WRONLY,
			0o600,
		)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return nil, "", err
		}
		return file, name, nil
	}
	return nil, "", errors.New("could not allocate a unique temporary filename")
}

func syncRoot(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	return errors.Join(syncErr, directory.Close())
}
