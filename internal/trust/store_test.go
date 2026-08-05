// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package trust

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestFileStoreAtomicallyCommitsAndRejectsStaleRevision(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	path := filepath.Join(dir, "state.json")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if initial.Version != StateVersion || initial.Revision != 0 {
		t.Fatalf("initial state = %#v", initial)
	}
	identity, _ := testIdentity(t)
	next := cloneSnapshot(initial)
	next.Identity = identity
	next.Revision = 1
	if err := store.Commit(0, next); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(0, next); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale Commit error = %v, want %v", err, ErrRevisionConflict)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Identity != identity || loaded.Revision != 1 {
		t.Fatalf("loaded state = %#v", loaded)
	}
	loaded.Identity.PeerID = "mutated"
	reloaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Identity != identity {
		t.Fatal("mutating loaded snapshot changed durable state")
	}
}

func TestFileStoreSerializesConcurrentRevisionZeroWriters(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	path := filepath.Join(dir, "state.json")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	identity, _ := testIdentity(t)
	next := emptySnapshot()
	next.Identity = identity
	next.Revision = 1

	var (
		waitGroup sync.WaitGroup
		results   = make(chan error, 2)
	)
	waitGroup.Add(2)
	for index := 0; index < 2; index++ {
		go func() {
			defer waitGroup.Done()
			results <- store.Commit(0, next)
		}()
	}
	waitGroup.Wait()
	close(results)
	var successes, conflicts int
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrRevisionConflict):
			conflicts++
		default:
			t.Fatalf("concurrent Commit error = %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes=%d conflicts=%d, want 1 each", successes, conflicts)
	}
}

func TestFileStoreRejectsUnknownSchemaPermissionsAndSymlink(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	_ = os.Chmod(directory, 0o700)
	path := filepath.Join(directory, "state.json")
	if err := os.WriteFile(path, []byte(`{"version":999}`), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); !errors.Is(err, ErrUnsupportedStateVersion) {
		t.Fatalf("unknown version Load error = %v", err)
	}

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("Load accepted non-owner-only state file")
	}

	target := filepath.Join(directory, "target.json")
	if err := os.WriteFile(target, []byte(`{"version":999}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	linkStore, err := NewFileStore(link)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := linkStore.Load(); err == nil {
		t.Fatal("Load accepted symbolic-link state path")
	}
}

func TestFileStoreRejectsRestoredPreRevocationStateAfterRestart(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	path := filepath.Join(dir, "state.json")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	local, _ := testIdentity(t)
	owner, ownerPrivate := testIdentity(t)
	var relationshipID string
	policy := AuthorizationPolicyFunc(func(
		_ context.Context,
		intent AuthorizationIntent,
	) (AuthorizationGrant, error) {
		switch intent.Operation {
		case OperationAdopt:
			grant := grantFor(intent, "rollback_owner_grant1")
			grant.OwnershipRole = OwnershipRoleOwner
			grant.RelationshipPhase = RelationshipPhaseAuthorized
			return grant, nil
		case OperationRevokeRelationship:
			if intent.RelationshipID != relationshipID {
				return AuthorizationGrant{}, errors.New("wrong rollback relationship")
			}
			return grantFor(intent, "rollback_revoke_001"), nil
		default:
			return AuthorizationGrant{}, errors.New("unexpected rollback operation")
		}
	})
	service, _, _ := newTestServiceOnStore(
		t,
		local,
		store,
		nil,
		policy,
		nil,
	)
	state := testTLSState(t, owner, ownerPrivate)
	relationship, err := service.AdoptDevice(
		context.Background(),
		state,
		local.PeerID,
	)
	if err != nil {
		t.Fatal(err)
	}
	relationshipID = relationship.ID
	preRevocation, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.RevokeTrust(
		context.Background(),
		state,
		relationshipID,
	); err != nil {
		t.Fatal(err)
	}
	revoked, err := service.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if revoked.Relationships[relationshipID].Phase != RelationshipPhaseRevoked {
		t.Fatal("relationship was not durably revoked before rollback simulation")
	}
	if err := os.WriteFile(path, preRevocation, 0o600); err != nil {
		t.Fatal(err)
	}
	restartedStore, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewService(ServiceConfig{
		Identity:                   local,
		Store:                      restartedStore,
		Policy:                     policy,
		PublicSnapshotBuilder:      &testBuilder{},
		Publisher:                  &testPublisher{rootCID: local.CanonicalIPNS},
		Clock:                      fixedClock{now: testNow},
		MaximumGrantLifetime:       time.Hour,
		MaximumCertificateLifetime: 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Open(context.Background()); !errors.Is(err, ErrStateRollback) {
		t.Fatalf("restored pre-revocation Open error = %v, want %v", err, ErrStateRollback)
	}
}

func TestFileStoreRejectsRevisionNotAdvancingByOne(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	path := filepath.Join(dir, "state.json")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	local, _ := testIdentity(t)
	initial, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	next := cloneSnapshot(initial)
	next.Identity = local
	next.Revision = 1
	if err := store.Commit(0, next); err != nil {
		t.Fatal(err)
	}
	skipAhead := cloneSnapshot(next)
	skipAhead.Revision = 5
	if err := store.Commit(1, skipAhead); err == nil {
		t.Fatal("store accepted revision jump from 1 to 5")
	}
}

func TestFileStorePreservesVersionAcrossCycles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	path := filepath.Join(dir, "state.json")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	local, _ := testIdentity(t)
	next := emptySnapshot()
	next.Identity = local
	next.Revision = 1
	if err := store.Commit(0, next); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Version != StateVersion {
		t.Fatalf("version = %d, want %d after commit", loaded.Version, StateVersion)
	}
	next2 := cloneSnapshot(loaded)
	next2.Revision = 2
	if err := store.Commit(1, next2); err != nil {
		t.Fatal(err)
	}
	reloaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Version != StateVersion || reloaded.Revision != 2 {
		t.Fatalf("reloaded = version=%d revision=%d, want version=%d revision=2",
			reloaded.Version, reloaded.Revision, StateVersion)
	}
}
