// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package ipfs

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPublisherRejectsCompletedTrustRevisionRollbackAndConflict(
	t *testing.T,
) {
	t.Parallel()
	config := testConfig(t)
	signer := newTestSigner(t)
	node := newFakeKuboNode(config, signer)
	store := newMemoryPublicationStore()
	publisher, err := NewPublisher(
		node,
		signer,
		store,
		config.RecordPolicy,
		&fakeClock{
			now: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC),
		},
	)
	if err != nil {
		t.Fatalf("create publisher: %v", err)
	}
	if _, err := publisher.Publish(
		context.Background(),
		testPublication(t, signer, 2, "revision-two"),
	); err != nil {
		t.Fatalf("publish revision two: %v", err)
	}
	published := len(node.records)
	if _, err := publisher.Publish(
		context.Background(),
		testPublication(t, signer, 1, "revision-one"),
	); !errors.Is(err, ErrTrustRevisionRollback) {
		t.Fatalf("older Trust revision error = %v, want rollback", err)
	}
	if _, err := publisher.Publish(
		context.Background(),
		testPublication(t, signer, 2, "different-content"),
	); !errors.Is(err, ErrTrustRevisionConflict) {
		t.Fatalf("conflicting Trust revision error = %v, want conflict", err)
	}
	if len(node.records) != published {
		t.Fatal("rejected Trust revision advanced IPNS")
	}
}

func TestPublisherPersistsTrustRevisionAntiRollbackAcrossRestart(
	t *testing.T,
) {
	t.Parallel()
	config := testConfig(t)
	signer := newTestSigner(t)
	store, err := NewFilePublicationStateStore(config.RepositoryPath)
	if err != nil {
		t.Fatalf("create file publication store: %v", err)
	}
	firstNode := newFakeKuboNode(config, signer)
	first, err := NewPublisher(
		firstNode,
		signer,
		store,
		config.RecordPolicy,
		&fakeClock{
			now: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC),
		},
	)
	if err != nil {
		t.Fatalf("create first publisher: %v", err)
	}
	if _, err := first.Publish(
		context.Background(),
		testPublication(t, signer, 4, "revision-four"),
	); err != nil {
		t.Fatalf("publish revision four: %v", err)
	}

	reopened, err := NewFilePublicationStateStore(config.RepositoryPath)
	if err != nil {
		t.Fatalf("reopen file publication store: %v", err)
	}
	secondNode := newFakeKuboNode(config, signer)
	second, err := NewPublisher(
		secondNode,
		signer,
		reopened,
		config.RecordPolicy,
		&fakeClock{
			now: time.Date(2026, 7, 28, 12, 1, 0, 0, time.UTC),
		},
	)
	if err != nil {
		t.Fatalf("create restarted publisher: %v", err)
	}
	if _, err := second.Publish(
		context.Background(),
		testPublication(t, signer, 3, "revision-three"),
	); !errors.Is(err, ErrTrustRevisionRollback) {
		t.Fatalf("restarted rollback error = %v, want rollback", err)
	}
	if len(secondNode.operations) != 0 {
		t.Fatalf(
			"restarted rollback reached Kubo operations: %v",
			secondNode.operations,
		)
	}
}

func TestPublisherRejectsPendingTrustRevisionRollbackAndConflict(
	t *testing.T,
) {
	t.Parallel()
	config := testConfig(t)
	signer := newTestSigner(t)
	node := newFakeKuboNode(config, signer)
	node.publishError = errors.New("offline")
	store := newMemoryPublicationStore()
	publisher, err := NewPublisher(
		node,
		signer,
		store,
		config.RecordPolicy,
		&fakeClock{
			now: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC),
		},
	)
	if err != nil {
		t.Fatalf("create publisher: %v", err)
	}
	if _, err := publisher.Publish(
		context.Background(),
		testPublication(t, signer, 6, "revision-six"),
	); err == nil {
		t.Fatal("offline publication unexpectedly succeeded")
	}
	attempts := len(node.attempts)
	if _, err := publisher.Publish(
		context.Background(),
		testPublication(t, signer, 5, "revision-five"),
	); !errors.Is(err, ErrTrustRevisionRollback) {
		t.Fatalf("older pending revision error = %v, want rollback", err)
	}
	if _, err := publisher.Publish(
		context.Background(),
		testPublication(t, signer, 6, "different-content"),
	); !errors.Is(err, ErrTrustRevisionConflict) {
		t.Fatalf("conflicting pending revision error = %v, want conflict", err)
	}
	if len(node.attempts) != attempts {
		t.Fatal("rejected pending Trust revision attempted IPNS publication")
	}
}
