// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package ipfs

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/ipfs/go-cid"
)

func TestPublisherPinsCompleteDAGBeforeMonotonicAdvance(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	signer := newTestSigner(t)
	node := newFakeKuboNode(config, signer)
	store := newMemoryPublicationStore()
	clock := &fakeClock{
		now: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC),
	}
	publisher, err := NewPublisher(
		node,
		signer,
		store,
		config.RecordPolicy,
		clock,
	)
	if err != nil {
		t.Fatalf("create publisher: %v", err)
	}
	publication := testPublication(t, signer, 1, "first")
	receipt, err := publisher.Publish(context.Background(), publication)
	if err != nil {
		t.Fatalf("publish snapshot: %v", err)
	}
	if receipt.PublicationID != publication.ID ||
		receipt.Digest != publication.Digest ||
		receipt.IPNSName != signer.Name() ||
		receipt.IPNSSequence != 1 ||
		receipt.RootCID == "" {
		t.Fatalf("publication receipt = %+v", receipt)
	}
	wantOperations := []string{"import", "inspect", "pin", "pinned", "publish"}
	if !slices.Equal(node.operations, wantOperations) {
		t.Fatalf("node operations = %v, want %v", node.operations, wantOperations)
	}
	state, err := store.Load()
	if err != nil {
		t.Fatalf("load completed state: %v", err)
	}
	if state.Pending != nil ||
		state.LastSequence != 1 ||
		state.HighSequence != 1 ||
		state.LastRootCID != receipt.RootCID {
		t.Fatalf("completed state = %+v", state)
	}
	root, err := canonicalRootCID(receipt.RootCID)
	if err != nil {
		t.Fatalf("decode receipt root: %v", err)
	}
	if err := ValidateSignedRecord(
		node.records[0],
		RecordValidation{
			ExpectedName: signer.Name(),
			ExpectedRoot: root,
			Now:          clock.Now(),
			Policy:       config.RecordPolicy,
			PublicKey:    signer.GetPublic(),
		},
	); err != nil {
		t.Fatalf("validate published signed record: %v", err)
	}

	beforeRecords := len(node.records)
	beforeImports := 0
	for _, operation := range node.operations {
		if operation == "import" {
			beforeImports++
		}
	}
	replayed, err := publisher.Publish(context.Background(), publication)
	if err != nil {
		t.Fatalf("replay completed publication: %v", err)
	}
	if replayed != receipt {
		t.Fatalf("idempotent receipt = %+v, want %+v", replayed, receipt)
	}
	afterImports := 0
	for _, operation := range node.operations {
		if operation == "import" {
			afterImports++
		}
	}
	if afterImports != beforeImports || len(node.records) != beforeRecords {
		t.Fatalf(
			"completed replay re-imported or advanced IPNS: operations=%v",
			node.operations,
		)
	}
}

func TestPublisherRetainsPendingRecordAndReplaysExactSequence(
	t *testing.T,
) {
	t.Parallel()
	config := testConfig(t)
	signer := newTestSigner(t)
	node := newFakeKuboNode(config, signer)
	node.publishError = errors.New("DHT unavailable")
	store := newMemoryPublicationStore()
	clock := &fakeClock{
		now: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC),
	}
	publisher, err := NewPublisher(
		node,
		signer,
		store,
		config.RecordPolicy,
		clock,
	)
	if err != nil {
		t.Fatalf("create publisher: %v", err)
	}
	publication := testPublication(t, signer, 1, "pending")
	if _, err := publisher.Publish(
		context.Background(),
		publication,
	); err == nil {
		t.Fatal("network publication failure was hidden")
	}
	state, err := store.Load()
	if err != nil {
		t.Fatalf("load pending state: %v", err)
	}
	if state.Pending == nil ||
		state.Pending.Record.Sequence != 1 ||
		state.LastSequence != 0 ||
		state.HighSequence != 1 {
		t.Fatalf("pending state = %+v", state)
	}
	firstDigest, err := node.attempts[0].Digest()
	if err != nil {
		t.Fatalf("digest first attempt: %v", err)
	}
	node.publishError = nil
	receipt, err := publisher.Publish(context.Background(), publication)
	if err != nil {
		t.Fatalf("resume pending publication: %v", err)
	}
	if receipt.IPNSSequence != 1 {
		t.Fatalf("resumed sequence = %d, want 1", receipt.IPNSSequence)
	}
	secondDigest, err := node.attempts[1].Digest()
	if err != nil {
		t.Fatalf("digest second attempt: %v", err)
	}
	if secondDigest != firstDigest {
		t.Fatal("pending replay did not reuse the exact signed record")
	}
	imports := 0
	for _, operation := range node.operations {
		if operation == "import" {
			imports++
		}
	}
	if imports != 1 {
		t.Fatalf("pending replay imported %d times, want 1", imports)
	}
}

func TestPublisherDoesNotOvertakeDifferentPendingPublication(
	t *testing.T,
) {
	t.Parallel()
	config := testConfig(t)
	signer := newTestSigner(t)
	node := newFakeKuboNode(config, signer)
	node.publishError = errors.New("publish uncertain")
	store := newMemoryPublicationStore()
	clock := &fakeClock{
		now: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC),
	}
	publisher, err := NewPublisher(
		node,
		signer,
		store,
		config.RecordPolicy,
		clock,
	)
	if err != nil {
		t.Fatalf("create publisher: %v", err)
	}
	if _, err := publisher.Publish(
		context.Background(),
		testPublication(t, signer, 1, "first"),
	); err == nil {
		t.Fatal("first publication unexpectedly succeeded")
	}
	operationCount := len(node.operations)
	_, err = publisher.Publish(
		context.Background(),
		testPublication(t, signer, 2, "second"),
	)
	if !errors.Is(err, ErrPublicationPending) {
		t.Fatalf("overtake error = %v, want pending rejection", err)
	}
	if len(node.operations) != operationCount {
		t.Fatal("different publication touched Kubo while one was pending")
	}
}

func TestPublisherRetainsPreviousRootOnLaterPublishFailure(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	signer := newTestSigner(t)
	node := newFakeKuboNode(config, signer)
	store := newMemoryPublicationStore()
	clock := &fakeClock{
		now: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC),
	}
	publisher, err := NewPublisher(
		node,
		signer,
		store,
		config.RecordPolicy,
		clock,
	)
	if err != nil {
		t.Fatalf("create publisher: %v", err)
	}
	first, err := publisher.Publish(
		context.Background(),
		testPublication(t, signer, 1, "first"),
	)
	if err != nil {
		t.Fatalf("publish first root: %v", err)
	}
	node.publishError = errors.New("network failure")
	if _, err := publisher.Publish(
		context.Background(),
		testPublication(t, signer, 2, "second"),
	); err == nil {
		t.Fatal("second network failure was hidden")
	}
	state, err := store.Load()
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if state.LastRootCID != first.RootCID ||
		state.LastSequence != first.IPNSSequence ||
		state.Pending == nil ||
		state.Pending.RootCID == first.RootCID {
		t.Fatalf("failure did not retain prior root: %+v", state)
	}
}

func TestPublisherRejectsPartialTamperedOrSymlinkDAGBeforePin(
	t *testing.T,
) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(SnapshotInspection) SnapshotInspection
	}{
		{
			name: "changed file bytes",
			mutate: func(value SnapshotInspection) SnapshotInspection {
				value.Files[0].Content[0] ^= 0x01
				return value
			},
		},
		{
			name: "changed block bytes",
			mutate: func(value SnapshotInspection) SnapshotInspection {
				value.Blocks[0].Bytes[0] ^= 0x01
				return value
			},
		},
		{
			name: "missing file",
			mutate: func(value SnapshotInspection) SnapshotInspection {
				value.Files = value.Files[1:]
				return value
			},
		},
		{
			name: "symlink entry",
			mutate: func(value SnapshotInspection) SnapshotInspection {
				value.Files[0].Type = "symlink"
				return value
			},
		},
		{
			name: "undeclared path",
			mutate: func(value SnapshotInspection) SnapshotInspection {
				value.Files[0].Path = "/secret"
				return value
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config := testConfig(t)
			signer := newTestSigner(t)
			node := newFakeKuboNode(config, signer)
			node.mutate = test.mutate
			store := newMemoryPublicationStore()
			publisher, err := NewPublisher(
				node,
				signer,
				store,
				config.RecordPolicy,
				&fakeClock{
					now: time.Date(
						2026, 7, 28, 12, 0, 0, 0, time.UTC,
					),
				},
			)
			if err != nil {
				t.Fatalf("create publisher: %v", err)
			}
			if _, err := publisher.Publish(
				context.Background(),
				testPublication(t, signer, 1, "tamper"),
			); err == nil {
				t.Fatal("invalid reachable DAG was published")
			}
			for _, operation := range node.operations {
				if operation == "pin" || operation == "publish" {
					t.Fatalf(
						"invalid DAG reached %q operation",
						operation,
					)
				}
			}
			state, err := store.Load()
			if err != nil {
				t.Fatalf("load state: %v", err)
			}
			if state.Pending != nil || state.HighSequence != 0 {
				t.Fatalf("invalid DAG reserved a sequence: %+v", state)
			}
		})
	}
}

func TestDAGValidationRejectsNonDirectoryRootCodec(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	signer := newTestSigner(t)
	node := newFakeKuboNode(config, signer)
	snapshot, err := NewPublicSnapshot(
		testPublication(t, signer, 1, "codec"),
		signer.Name(),
	)
	if err != nil {
		t.Fatalf("create snapshot: %v", err)
	}
	imported, err := node.ImportPublicSnapshot(
		context.Background(),
		snapshot,
	)
	if err != nil {
		t.Fatalf("import fake snapshot: %v", err)
	}
	inspection, err := node.InspectPublicSnapshot(
		context.Background(),
		imported.Root,
	)
	if err != nil {
		t.Fatalf("inspect fake snapshot: %v", err)
	}
	rootBlock := &inspection.Blocks[len(inspection.Blocks)-1]
	rawRoot := testCIDValueWithCodec(rootBlock.Bytes, cid.Raw)
	rootBlock.CID = rawRoot
	inspection.Root = rawRoot
	if err := validateImportedSnapshot(
		ImportedSnapshot{Root: rawRoot},
		snapshot,
		inspection,
	); err == nil {
		t.Fatal("raw block was accepted as an immutable directory root")
	}
}

func TestPublisherRefreshesExpiredPendingRecordWithoutSequenceReuse(
	t *testing.T,
) {
	t.Parallel()
	config := testConfig(t)
	signer := newTestSigner(t)
	node := newFakeKuboNode(config, signer)
	node.publishError = errors.New("offline")
	store := newMemoryPublicationStore()
	clock := &fakeClock{
		now: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC),
	}
	publisher, err := NewPublisher(
		node,
		signer,
		store,
		config.RecordPolicy,
		clock,
	)
	if err != nil {
		t.Fatalf("create publisher: %v", err)
	}
	publication := testPublication(t, signer, 1, "refresh")
	if _, err := publisher.Publish(
		context.Background(),
		publication,
	); err == nil {
		t.Fatal("offline publish unexpectedly succeeded")
	}
	clock.Advance(config.RecordPolicy.Validity + time.Second)
	node.publishError = nil
	receipt, err := publisher.Publish(context.Background(), publication)
	if err != nil {
		t.Fatalf("refresh expired pending record: %v", err)
	}
	if receipt.IPNSSequence != 2 {
		t.Fatalf("refreshed sequence = %d, want 2", receipt.IPNSSequence)
	}
	if node.attempts[0].Sequence != 1 ||
		node.attempts[1].Sequence != 2 {
		t.Fatalf("record attempts = %+v", node.attempts)
	}
}

func TestPublisherDoesNotAcceptExpiredCompletedRecord(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	signer := newTestSigner(t)
	node := newFakeKuboNode(config, signer)
	store := newMemoryPublicationStore()
	clock := &fakeClock{
		now: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC),
	}
	publisher, err := NewPublisher(
		node,
		signer,
		store,
		config.RecordPolicy,
		clock,
	)
	if err != nil {
		t.Fatalf("create publisher: %v", err)
	}
	publication := testPublication(t, signer, 1, "expired-complete")
	if _, err := publisher.Publish(
		context.Background(),
		publication,
	); err != nil {
		t.Fatalf("publish initial record: %v", err)
	}
	clock.Advance(config.RecordPolicy.Validity + time.Second)
	recordCount := len(node.records)
	if _, err := publisher.Publish(
		context.Background(),
		publication,
	); err == nil {
		t.Fatal("expired completed record was accepted")
	}
	if len(node.records) != recordCount {
		t.Fatal("expired completed replay advanced IPNS implicitly")
	}
}

func TestPublisherRecoversWhenPublishSucceededButCommitFailed(
	t *testing.T,
) {
	t.Parallel()
	config := testConfig(t)
	signer := newTestSigner(t)
	node := newFakeKuboNode(config, signer)
	store := newMemoryPublicationStore()
	store.failCommit[2] = errors.New("directory fsync failed")
	clock := &fakeClock{
		now: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC),
	}
	publisher, err := NewPublisher(
		node,
		signer,
		store,
		config.RecordPolicy,
		clock,
	)
	if err != nil {
		t.Fatalf("create publisher: %v", err)
	}
	publication := testPublication(t, signer, 1, "uncertain")
	if _, err := publisher.Publish(
		context.Background(),
		publication,
	); err == nil {
		t.Fatal("failed completion commit was hidden")
	}
	state, err := store.Load()
	if err != nil {
		t.Fatalf("load pending state: %v", err)
	}
	if state.Pending == nil || state.LastSequence != 0 {
		t.Fatalf("uncertain publication state = %+v", state)
	}
	receipt, err := publisher.Publish(context.Background(), publication)
	if err != nil {
		t.Fatalf("recover uncertain publication: %v", err)
	}
	if receipt.IPNSSequence != 1 || len(node.records) != 2 {
		t.Fatalf(
			"recovered receipt=%+v successful records=%d",
			receipt,
			len(node.records),
		)
	}
	first, err := node.records[0].Digest()
	if err != nil {
		t.Fatalf("digest first record: %v", err)
	}
	second, err := node.records[1].Digest()
	if err != nil {
		t.Fatalf("digest second record: %v", err)
	}
	if first != second {
		t.Fatal("uncertain network result did not replay exact record")
	}
}
