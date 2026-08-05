// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package ipfs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFilePublicationStateStorePersistsPendingAndCompletedState(
	t *testing.T,
) {
	t.Parallel()
	config := testConfig(t)
	signer := newTestSigner(t)
	store, err := NewFilePublicationStateStore(config.RepositoryPath)
	if err != nil {
		t.Fatalf("create publication store: %v", err)
	}
	empty, err := store.Load()
	if err != nil {
		t.Fatalf("load empty state: %v", err)
	}
	if empty.Version != PublicationStateVersion ||
		empty.Revision != 0 {
		t.Fatalf("empty state = %+v", empty)
	}
	root := testCID(t, []byte("pinned root"))
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	record, err := CreateSignedRecord(
		context.Background(),
		signer,
		root,
		1,
		now,
		config.RecordPolicy,
	)
	if err != nil {
		t.Fatalf("create signed record: %v", err)
	}
	publicationID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	pending := PublicationState{
		Version:      PublicationStateVersion,
		Revision:     1,
		IPNSName:     signer.Name(),
		HighSequence: 1,
		Pending: &PendingPublication{
			PublicationID: publicationID,
			Digest:        publicationID,
			TrustRevision: 7,
			RootCID:       root.String(),
			Record:        record,
		},
	}
	if err := store.Commit(0, pending); err != nil {
		t.Fatalf("commit pending state: %v", err)
	}
	reloaded, err := store.Load()
	if err != nil {
		t.Fatalf("reload pending state: %v", err)
	}
	if reloaded.Pending == nil ||
		reloaded.Pending.Record.Sequence != 1 ||
		reloaded.HighSequence != 1 {
		t.Fatalf("reloaded pending state = %+v", reloaded)
	}

	completed := reloaded.Clone()
	completed.Revision = 2
	completed.LastSequence = 1
	completed.LastPublicationID = publicationID
	completed.LastDigest = publicationID
	completed.LastTrustRevision = reloaded.Pending.TrustRevision
	completed.LastRootCID = root.String()
	lastRecord := record.Clone()
	completed.LastRecord = &lastRecord
	completed.Pending = nil
	if err := store.Commit(1, completed); err != nil {
		t.Fatalf("commit completed state: %v", err)
	}
	reloaded, err = store.Load()
	if err != nil {
		t.Fatalf("reload completed state: %v", err)
	}
	if reloaded.LastSequence != 1 ||
		reloaded.LastTrustRevision != 7 ||
		reloaded.LastRootCID != root.String() ||
		reloaded.Pending != nil {
		t.Fatalf("reloaded completed state = %+v", reloaded)
	}
	info, err := os.Lstat(
		filepath.Join(config.RepositoryPath, publicationStateFilename),
	)
	if err != nil {
		t.Fatalf("inspect state file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestFilePublicationStateStoreRejectsRevisionConflict(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	store, err := NewFilePublicationStateStore(config.RepositoryPath)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	next := emptyPublicationState()
	next.Revision = 1
	if err := store.Commit(0, next); err != nil {
		t.Fatalf("commit initial state: %v", err)
	}
	stale := next.Clone()
	stale.Revision = 1
	err = store.Commit(0, stale)
	if !errors.Is(err, ErrPublicationStateConflict) {
		t.Fatalf("stale commit error = %v, want revision conflict", err)
	}
}

func TestFilePublicationStateStoreRejectsUnknownVersionAndSymlink(
	t *testing.T,
) {
	t.Parallel()
	t.Run("unknown version", func(t *testing.T) {
		t.Parallel()
		config := testConfig(t)
		path := filepath.Join(
			config.RepositoryPath,
			publicationStateFilename,
		)
		if err := os.WriteFile(path, []byte(
			"{\"version\":99,\"revision\":0,\"high_sequence\":0,\"last_sequence\":0}\n",
		), 0o600); err != nil {
			t.Fatalf("write unknown state: %v", err)
		}
		store, err := NewFilePublicationStateStore(config.RepositoryPath)
		if err != nil {
			t.Fatalf("create store: %v", err)
		}
		if _, err := store.Load(); err == nil {
			t.Fatal("unknown state version was accepted")
		}
	})
	t.Run("state symlink", func(t *testing.T) {
		t.Parallel()
		config := testConfig(t)
		outside := filepath.Join(t.TempDir(), "outside")
		if err := os.WriteFile(outside, []byte("{}"), 0o600); err != nil {
			t.Fatalf("write outside state: %v", err)
		}
		if err := os.Symlink(
			outside,
			filepath.Join(
				config.RepositoryPath,
				publicationStateFilename,
			),
		); err != nil {
			t.Fatalf("create state symlink: %v", err)
		}
		store, err := NewFilePublicationStateStore(config.RepositoryPath)
		if err != nil {
			t.Fatalf("create store: %v", err)
		}
		if _, err := store.Load(); err == nil {
			t.Fatal("symlink publication state was accepted")
		}
	})
}

func TestFilePublicationStateStoreRejectsPermissiveRepository(
	t *testing.T,
) {
	t.Parallel()
	config := testConfig(t)
	if err := os.Chmod(config.RepositoryPath, 0o755); err != nil {
		t.Fatalf("make repository permissive: %v", err)
	}
	store, err := NewFilePublicationStateStore(config.RepositoryPath)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("permissive Kubo repository was accepted")
	}
}
