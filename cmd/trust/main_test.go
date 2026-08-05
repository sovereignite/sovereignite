// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multibase"

	"github.com/sovereignite/sovereignite/internal/keymanager"
	"github.com/sovereignite/sovereignite/internal/tpm"
)

type stubBackend struct{}

func (stubBackend) Supports(context.Context, tpm.Algorithm) error {
	return nil
}

func (stubBackend) CreatePersistent(
	context.Context, tpm.Handle, tpm.Template, tpm.PreparePersistent,
) (tpm.Public, error) {
	return tpm.Public{}, errors.New("stub TPM: create not supported")
}

func (stubBackend) ReadPublic(
	context.Context, tpm.Handle,
) (tpm.Public, error) {
	return tpm.Public{}, tpm.ErrHandleNotFound
}

func (stubBackend) Sign(
	context.Context, tpm.SignRequest,
) ([]byte, error) {
	return nil, errors.New("stub TPM: sign not supported")
}

func (stubBackend) EvictPersistent(
	context.Context, tpm.ObjectReference,
) error {
	return tpm.ErrHandleNotFound
}

func (stubBackend) Close() error { return nil }

func generateTestIdentity(t *testing.T) (ipns, peerID string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	libp2pPub, err := crypto.UnmarshalEd25519PublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := peer.IDFromPublicKey(libp2pPub)
	if err != nil {
		t.Fatal(err)
	}
	keyCID := peer.ToCid(pid)
	ipnsName, err := keyCID.StringOfBase(multibase.Base36)
	if err != nil {
		t.Fatal(err)
	}
	return ipnsName, pid.String()
}

func privateTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func installStubTPM(t *testing.T) {
	t.Helper()
	origOpenTPM := openTPM
	origNewKeyStore := newKeyStore
	origNewManager := newManager
	t.Cleanup(func() {
		openTPM = origOpenTPM
		newKeyStore = origNewKeyStore
		newManager = origNewManager
	})
	openTPM = func(tpm.GoTPMConfig) (tpm.Backend, error) {
		return stubBackend{}, nil
	}
	newKeyStore = func(path string) (*keymanager.FileStore, error) {
		return keymanager.NewFileStore(path)
	}
	newManager = func(
		backend tpm.Backend,
		store keymanager.Store,
		policies []keymanager.RolePolicy,
		certificatePolicy keymanager.CertificatePolicy,
		clock keymanager.Clock,
	) (*keymanager.Manager, error) {
		return keymanager.NewManager(backend, store, policies, certificatePolicy, clock)
	}
}

func TestRunStartsWithWiredKeyManager(t *testing.T) {
	ipns, peerID := generateTestIdentity(t)
	t.Setenv("SOVEREIGNITE_CANONICAL_IPNS", ipns)
	t.Setenv("SOVEREIGNITE_PEER_ID", peerID)

	dir := privateTempDir(t)
	metadataPath := filepath.Join(dir, "metadata.json")
	installStubTPM(t)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- run(
			[]string{"--metadata-path", metadataPath},
			ctx,
		)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("run() with wired key manager: unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run() did not stop after context cancellation")
	}
}

func TestRunFailsClosedWhenKeyManagerUnavailable(t *testing.T) {
	ipns, peerID := generateTestIdentity(t)
	t.Setenv("SOVEREIGNITE_CANONICAL_IPNS", ipns)
	t.Setenv("SOVEREIGNITE_PEER_ID", peerID)

	origOpenTPM := openTPM
	t.Cleanup(func() { openTPM = origOpenTPM })

	openTPM = func(tpm.GoTPMConfig) (tpm.Backend, error) {
		return nil, tpm.ErrAdapterUnavailable
	}

	err := run(nil, context.Background())
	if !errors.Is(err, tpm.ErrAdapterUnavailable) {
		t.Fatalf("run() error = %v, want adapter unavailable", err)
	}
}

func TestRunRejectsUnplannedCommands(t *testing.T) {
	t.Parallel()

	origOpenTPM := openTPM
	t.Cleanup(func() { openTPM = origOpenTPM })
	openTPM = func(tpm.GoTPMConfig) (tpm.Backend, error) {
		return stubBackend{}, nil
	}

	if err := run([]string{"serve-plaintext"}, nil); err == nil {
		t.Fatal("run() accepted an unplanned command")
	}
}

func TestMetadataPathEmptyFailsClosed(t *testing.T) {
	ipns, peerID := generateTestIdentity(t)
	t.Setenv("SOVEREIGNITE_CANONICAL_IPNS", ipns)
	t.Setenv("SOVEREIGNITE_PEER_ID", peerID)

	installStubTPM(t)

	err := run([]string{"--metadata-path", ""}, context.Background())
	if err == nil {
		t.Fatal("run() accepted empty metadata path")
	}
}

func TestMetadataDirectoryRequiresPrivatePermissions(t *testing.T) {
	ipns, peerID := generateTestIdentity(t)
	t.Setenv("SOVEREIGNITE_CANONICAL_IPNS", ipns)
	t.Setenv("SOVEREIGNITE_PEER_ID", peerID)

	installStubTPM(t)

	// Create a directory with overly permissive permissions.
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	metadataPath := filepath.Join(dir, "metadata.json")

	err := run([]string{"--metadata-path", metadataPath}, context.Background())
	if err == nil {
		t.Fatal("run() accepted non-private metadata directory")
	}
}
