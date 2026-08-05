// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package ipfs

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"

	"github.com/sovereignite/sovereignite/internal/trust"
)

func TestP2_04_PublicationBuildsCompleteDAGBeforeAdvance(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	signer := newTestSigner(t)
	node := newFakeKuboNode(config, signer)
	store := newMemoryPublicationStore()
	clock := &fakeClock{
		now: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC),
	}
	publisher, err := NewPublisher(node, signer, store, config.RecordPolicy, clock)
	if err != nil {
		t.Fatalf("create publisher: %v", err)
	}
	publication := testPublication(t, signer, 1, "dag-complete")
	receipt, err := publisher.Publish(context.Background(), publication)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if receipt.RootCID == "" {
		t.Fatal("receipt has no root CID")
	}
	importCount := 0
	inspectCount := 0
	pinCount := 0
	pinnedCount := 0
	publishCount := 0
	for _, op := range node.operations {
		switch op {
		case "import":
			importCount++
		case "inspect":
			inspectCount++
		case "pin":
			pinCount++
		case "pinned":
			pinnedCount++
		case "publish":
			publishCount++
		}
	}
	if importCount != 1 {
		t.Fatalf("import count = %d, want 1", importCount)
	}
	if inspectCount != 1 {
		t.Fatalf("inspect count = %d, want 1", inspectCount)
	}
	if pinCount != 1 {
		t.Fatalf("pin count = %d, want 1", pinCount)
	}
	if pinnedCount != 1 {
		t.Fatalf("pinned count = %d, want 1", pinnedCount)
	}
	if publishCount != 1 {
		t.Fatalf("publish count = %d, want 1", publishCount)
	}
	state, err := store.Load()
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if state.LastRootCID != receipt.RootCID {
		t.Fatalf("state root %s != receipt root %s", state.LastRootCID, receipt.RootCID)
	}
	if state.LastSequence != 1 {
		t.Fatalf("state sequence = %d, want 1", state.LastSequence)
	}
	if state.Pending != nil {
		t.Fatal("completed publication still has pending record")
	}
}

func TestP2_04_IPNSRecordSignedByTPM(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	signer := newTestSigner(t)
	node := newFakeKuboNode(config, signer)
	store := newMemoryPublicationStore()
	clock := &fakeClock{
		now: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC),
	}
	publisher, err := NewPublisher(node, signer, store, config.RecordPolicy, clock)
	if err != nil {
		t.Fatalf("create publisher: %v", err)
	}
	publication := testPublication(t, signer, 1, "tpm-signed")
	if _, err := publisher.Publish(context.Background(), publication); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if len(node.records) != 1 {
		t.Fatalf("record count = %d, want 1", len(node.records))
	}
	record := node.records[0]
	if record.Name != signer.Name() {
		t.Fatalf("record name = %s, want %s", record.Name, signer.Name())
	}
	if record.Signature == nil {
		t.Fatal("record has no signature")
	}
	root, err := record.RootCID()
	if err != nil {
		t.Fatalf("parse record root: %v", err)
	}
	if err := ValidateSignedRecord(record, RecordValidation{
		ExpectedName: signer.Name(),
		ExpectedRoot: root,
		Now:          clock.Now(),
		Policy:       config.RecordPolicy,
		PublicKey:    signer.GetPublic(),
	}); err != nil {
		t.Fatalf("validate TPM-signed record: %v", err)
	}
	otherPrivate, otherPublic, err := libp2pcrypto.GenerateKeyPair(libp2pcrypto.Ed25519, -1)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}
	_ = otherPrivate
	if err := ValidateSignedRecord(record, RecordValidation{
		ExpectedName: signer.Name(),
		ExpectedRoot: root,
		Now:          clock.Now(),
		Policy:       config.RecordPolicy,
		PublicKey:    otherPublic,
	}); err == nil {
		t.Fatal("record validated with wrong public key")
	}
}

func TestP2_04_MonotonicSequenceEnforcement(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	signer := newTestSigner(t)
	node := newFakeKuboNode(config, signer)
	store := newMemoryPublicationStore()
	clock := &fakeClock{
		now: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC),
	}
	publisher, err := NewPublisher(node, signer, store, config.RecordPolicy, clock)
	if err != nil {
		t.Fatalf("create publisher: %v", err)
	}
	r1, err := publisher.Publish(context.Background(), testPublication(t, signer, 1, "seq-one"))
	if err != nil {
		t.Fatalf("publish first: %v", err)
	}
	if r1.IPNSSequence != 1 {
		t.Fatalf("first sequence = %d, want 1", r1.IPNSSequence)
	}
	r2, err := publisher.Publish(context.Background(), testPublication(t, signer, 2, "seq-two"))
	if err != nil {
		t.Fatalf("publish second: %v", err)
	}
	if r2.IPNSSequence != 2 {
		t.Fatalf("second sequence = %d, want 2", r2.IPNSSequence)
	}
	r3, err := publisher.Publish(context.Background(), testPublication(t, signer, 3, "seq-three"))
	if err != nil {
		t.Fatalf("publish third: %v", err)
	}
	if r3.IPNSSequence != 3 {
		t.Fatalf("third sequence = %d, want 3", r3.IPNSSequence)
	}
	state, err := store.Load()
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if state.HighSequence != 3 {
		t.Fatalf("high sequence = %d, want 3", state.HighSequence)
	}
	if state.LastSequence != 3 {
		t.Fatalf("last sequence = %d, want 3", state.LastSequence)
	}
	for i, record := range node.records {
		seq := uint64(i + 1)
		if record.Sequence != seq {
			t.Fatalf("record %d sequence = %d, want %d", i, record.Sequence, seq)
		}
	}
}

func TestP2_04_ReplayIdempotency(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	signer := newTestSigner(t)
	node := newFakeKuboNode(config, signer)
	store := newMemoryPublicationStore()
	clock := &fakeClock{
		now: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC),
	}
	publisher, err := NewPublisher(node, signer, store, config.RecordPolicy, clock)
	if err != nil {
		t.Fatalf("create publisher: %v", err)
	}
	publication := testPublication(t, signer, 1, "idempotent")
	first, err := publisher.Publish(context.Background(), publication)
	if err != nil {
		t.Fatalf("first publish: %v", err)
	}
	recordsAfterFirst := len(node.records)
	importsAfterFirst := 0
	for _, op := range node.operations {
		if op == "import" {
			importsAfterFirst++
		}
	}
	second, err := publisher.Publish(context.Background(), publication)
	if err != nil {
		t.Fatalf("replay publish: %v", err)
	}
	if first != second {
		t.Fatalf("replay receipt = %+v, want identical %+v", second, first)
	}
	importsAfterReplay := 0
	for _, op := range node.operations {
		if op == "import" {
			importsAfterReplay++
		}
	}
	if importsAfterReplay != importsAfterFirst {
		t.Fatalf("replay added imports: %d -> %d", importsAfterFirst, importsAfterReplay)
	}
	if len(node.records) != recordsAfterFirst {
		t.Fatalf("replay advanced IPNS: %d -> %d records", recordsAfterFirst, len(node.records))
	}
}

func TestP2_04_FailureRetainsPriorRoot(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	signer := newTestSigner(t)
	node := newFakeKuboNode(config, signer)
	store := newMemoryPublicationStore()
	clock := &fakeClock{
		now: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC),
	}
	publisher, err := NewPublisher(node, signer, store, config.RecordPolicy, clock)
	if err != nil {
		t.Fatalf("create publisher: %v", err)
	}
	first, err := publisher.Publish(context.Background(), testPublication(t, signer, 1, "retain-one"))
	if err != nil {
		t.Fatalf("first publish: %v", err)
	}
	node.publishError = errors.New("network failure")
	if _, err := publisher.Publish(context.Background(), testPublication(t, signer, 2, "retain-two")); err == nil {
		t.Fatal("failure was hidden")
	}
	state, err := store.Load()
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if state.LastRootCID != first.RootCID {
		t.Fatalf("failure changed root: got %s, want %s", state.LastRootCID, first.RootCID)
	}
	if state.LastSequence != first.IPNSSequence {
		t.Fatalf("failure changed sequence: got %d, want %d", state.LastSequence, first.IPNSSequence)
	}
	if state.Pending == nil {
		t.Fatal("failure did not preserve pending record")
	}
	if state.Pending.RootCID == first.RootCID {
		t.Fatal("pending record has same root as completed")
	}
}

func TestP2_04_PathTraversalRejection(t *testing.T) {
	t.Parallel()
	traversalPaths := []string{
		"/../../../etc/passwd",
		"/spiffe-bundle.json/../../../secret",
		"/updates/../../etc/shadow",
		"/crl/../../private/key",
		"/device/../../../etc/passwd/identity",
		"/spiffe-bundle.json%00",
		"/ocsp/../../../../secret",
		"/.well-known/sovereignite/../../../etc/passwd",
	}
	for _, path := range traversalPaths {
		if _, err := validateAllowedPath(path); err == nil {
			t.Fatalf("traversal path %q was accepted", path)
		}
	}
	config := testConfig(t)
	signer := newTestSigner(t)
	node := newFakeKuboNode(config, signer)
	store := newMemoryPublicationStore()
	publisher, err := NewPublisher(node, signer, store, config.RecordPolicy, &fakeClock{
		now: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("create publisher: %v", err)
	}
	for _, mutation := range []struct {
		name   string
		mutate func(SnapshotInspection) SnapshotInspection
	}{
		{
			name: "undeclared path in DAG",
			mutate: func(v SnapshotInspection) SnapshotInspection {
				v.Files[0].Path = "/secret/traversal"
				return v
			},
		},
		{
			name: "path with traversal in DAG",
			mutate: func(v SnapshotInspection) SnapshotInspection {
				v.Files[0].Path = "/spiffe-bundle.json/../../../etc/passwd"
				return v
			},
		},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			t.Parallel()
			node.mutate = mutation.mutate
			_, err := publisher.Publish(context.Background(), testPublication(t, signer, 1, "traversal"))
			if err == nil {
				t.Fatal("traversal DAG was published")
			}
			for _, op := range node.operations {
				if op == "pin" || op == "publish" {
					t.Fatalf("traversal DAG reached %q operation", op)
				}
			}
		})
	}
}

func TestP2_04_SymlinkRejection(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	signer := newTestSigner(t)
	node := newFakeKuboNode(config, signer)
	store := newMemoryPublicationStore()
	publisher, err := NewPublisher(node, signer, store, config.RecordPolicy, &fakeClock{
		now: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("create publisher: %v", err)
	}
	node.mutate = func(v SnapshotInspection) SnapshotInspection {
		for i := range v.Files {
			v.Files[i].Type = "symlink"
		}
		return v
	}
	_, err = publisher.Publish(context.Background(), testPublication(t, signer, 1, "symlink"))
	if err == nil {
		t.Fatal("symlink DAG was published")
	}
	state, err := store.Load()
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if state.Pending != nil || state.HighSequence != 0 {
		t.Fatalf("symlink DAG reserved a sequence: %+v", state)
	}
}

func TestP2_04_SecretRejectionPEMInDAG(t *testing.T) {
	t.Parallel()
	pemMarkers := []struct {
		name    string
		content []byte
	}{
		{
			name:    "RSA private key PEM",
			content: []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBALRiMLAHudeSA/x3hB2f+2NRkJLA\n-----END RSA PRIVATE KEY-----"),
		},
		{
			name:    "encrypted private key PEM",
			content: []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIBnTCB+wIBATCBmAYHKoZIzj0CATENDgEtcGFzc3dvcmQ=\n-----END ENCRYPTED PRIVATE KEY-----"),
		},
		{
			name:    "EC private key PEM",
			content: []byte("-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIILqJZaH2P9sJXe0xX0Z2g8H7t9cK4d6e5f3g2h1\n-----END EC PRIVATE KEY-----"),
		},
		{
			name:    "OpenSSH private key PEM",
			content: []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA=\n-----END OPENSSH PRIVATE KEY-----"),
		},
	}
	for _, test := range pemMarkers {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if !containsPrivateKeyPEM(test.content) {
				t.Fatalf("PEM content not detected as private material: %s", test.content)
			}
		})
	}
	config := testConfig(t)
	signer := newTestSigner(t)
	node := newFakeKuboNode(config, signer)
	store := newMemoryPublicationStore()
	publisher, err := NewPublisher(node, signer, store, config.RecordPolicy, &fakeClock{
		now: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("create publisher: %v", err)
	}
	node.mutate = func(v SnapshotInspection) SnapshotInspection {
		for i := range v.Blocks {
			v.Blocks[i].Bytes = append(v.Blocks[i].Bytes,
				[]byte("-----BEGIN PRIVATE KEY-----\nMIIBogIBAAJBALRiMLAHudeSA/x3hB2f+2NRkJLA\n-----END PRIVATE KEY-----")...,
			)
		}
		return v
	}
	_, err = publisher.Publish(context.Background(), testPublication(t, signer, 1, "secret"))
	if err == nil {
		t.Fatal("DAG with private key material was published")
	}
	for _, op := range node.operations {
		if op == "pin" || op == "publish" {
			t.Fatalf("secret DAG reached %q operation", op)
		}
	}
}

func TestP2_04_SecretRejectionPrivateFieldsInDocument(t *testing.T) {
	t.Parallel()
	privateFields := []struct {
		name    string
		content []byte
	}{
		{
			name:    "private_key field",
			content: []byte(`{"private_key":"canary-value"}`),
		},
		{
			name:    "privateKey field",
			content: []byte(`{"privateKey":"canary-value"}`),
		},
		{
			name:    "cluster_secret field",
			content: []byte(`{"cluster_secret":"canary-value"}`),
		},
		{
			name:    "credential field",
			content: []byte(`{"credential":"canary-value"}`),
		},
		{
			name:    "private PEM in JSON",
			content: []byte(`{"value":"-----BEGIN PRIVATE KEY-----\ncanary"}`),
		},
	}
	for _, test := range privateFields {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := trust.NewPublicDocument(
				pathDeviceDocument,
				mediaTypeJSON,
				test.content,
			)
			if err == nil {
				t.Fatalf("private field content %q was accepted as public", test.name)
			}
		})
	}
}

func TestP2_04_WrongCIDRejection(t *testing.T) {
	t.Parallel()
	signer := newTestSigner(t)
	root := testCID(t, []byte("correct root"))
	wrongRoot := testCID(t, []byte("wrong root"))
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	policy := RecordPolicy{
		Validity:     time.Hour,
		MaxValidity:  time.Hour,
		MaxStaleness: time.Hour,
		ClockSkew:    time.Minute,
	}
	record, err := CreateSignedRecord(context.Background(), signer, root, 1, now, policy)
	if err != nil {
		t.Fatalf("create record: %v", err)
	}
	if err := ValidateSignedRecord(record, RecordValidation{
		ExpectedName: signer.Name(),
		ExpectedRoot: wrongRoot,
		Now:          now,
		Policy:       policy,
		PublicKey:    signer.GetPublic(),
	}); err == nil {
		t.Fatal("wrong CID was accepted")
	}
}

func TestP2_04_WrongSignatureRejection(t *testing.T) {
	t.Parallel()
	signer := newTestSigner(t)
	other := newTestSigner(t)
	root := testCID(t, []byte("signed root"))
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	policy := RecordPolicy{
		Validity:     time.Hour,
		MaxValidity:  time.Hour,
		MaxStaleness: time.Hour,
		ClockSkew:    time.Minute,
	}
	record, err := CreateSignedRecord(context.Background(), signer, root, 1, now, policy)
	if err != nil {
		t.Fatalf("create record: %v", err)
	}
	tampered := record.Clone()
	tampered.Signature[0] ^= 0xFF
	if err := ValidateSignedRecord(tampered, RecordValidation{
		ExpectedName: signer.Name(),
		ExpectedRoot: root,
		Now:          now,
		Policy:       policy,
		PublicKey:    signer.GetPublic(),
	}); err == nil {
		t.Fatal("tampered signature was accepted")
	}
	wrongName := record.Clone()
	wrongName.Name = other.Name()
	if err := ValidateSignedRecord(wrongName, RecordValidation{
		ExpectedName: signer.Name(),
		ExpectedRoot: root,
		Now:          now,
		Policy:       policy,
		PublicKey:    signer.GetPublic(),
	}); err == nil {
		t.Fatal("wrong name was accepted")
	}
}

func TestP2_04_ExpiredRecordRejection(t *testing.T) {
	t.Parallel()
	signer := newTestSigner(t)
	root := testCID(t, []byte("expiring root"))
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	policy := RecordPolicy{
		Validity:     time.Hour,
		MaxValidity:  time.Hour,
		MaxStaleness: time.Hour,
		ClockSkew:    time.Minute,
	}
	record, err := CreateSignedRecord(context.Background(), signer, root, 1, now, policy)
	if err != nil {
		t.Fatalf("create record: %v", err)
	}
	if err := ValidateSignedRecord(record, RecordValidation{
		ExpectedName: signer.Name(),
		ExpectedRoot: root,
		Now:          record.ValidUntil.Add(time.Second),
		Policy:       policy,
		PublicKey:    signer.GetPublic(),
	}); err == nil {
		t.Fatal("expired record was accepted")
	}
	if err := ValidateSignedRecord(record, RecordValidation{
		ExpectedName: signer.Name(),
		ExpectedRoot: root,
		Now:          now,
		Policy:       policy,
		PublicKey:    signer.GetPublic(),
	}); err != nil {
		t.Fatalf("valid record was rejected: %v", err)
	}
}

func TestP2_04_LowerSequenceRejection(t *testing.T) {
	t.Parallel()
	signer := newTestSigner(t)
	root := testCID(t, []byte("sequence root"))
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	policy := RecordPolicy{
		Validity:     time.Hour,
		MaxValidity:  time.Hour,
		MaxStaleness: time.Hour,
		ClockSkew:    time.Minute,
	}
	record, err := CreateSignedRecord(context.Background(), signer, root, 5, now, policy)
	if err != nil {
		t.Fatalf("create record: %v", err)
	}
	if err := ValidateSignedRecord(record, RecordValidation{
		ExpectedName:     signer.Name(),
		ExpectedRoot:     root,
		PreviousSequence: 5,
		Now:              now,
		Policy:           policy,
		PublicKey:        signer.GetPublic(),
	}); err == nil {
		t.Fatal("equal sequence was accepted")
	}
	if err := ValidateSignedRecord(record, RecordValidation{
		ExpectedName:     signer.Name(),
		ExpectedRoot:     root,
		PreviousSequence: 6,
		Now:              now,
		Policy:           policy,
		PublicKey:        signer.GetPublic(),
	}); err == nil {
		t.Fatal("lower sequence was accepted")
	}
	if err := ValidateSignedRecord(record, RecordValidation{
		ExpectedName:     signer.Name(),
		ExpectedRoot:     root,
		PreviousSequence: 4,
		Now:              now,
		Policy:           policy,
		PublicKey:        signer.GetPublic(),
	}); err != nil {
		t.Fatalf("higher sequence was rejected: %v", err)
	}
}

func TestP2_04_CanaryDecodedDAGContent(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	signer := newTestSigner(t)
	node := newFakeKuboNode(config, signer)
	store := newMemoryPublicationStore()
	clock := &fakeClock{
		now: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC),
	}
	publisher, err := NewPublisher(node, signer, store, config.RecordPolicy, clock)
	if err != nil {
		t.Fatalf("create publisher: %v", err)
	}
	publication := testPublication(t, signer, 1, "canary-test")
	if _, err := publisher.Publish(context.Background(), publication); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if len(node.records) != 1 {
		t.Fatalf("record count = %d, want 1", len(node.records))
	}
	record := node.records[0]
	recordRoot, err := record.RootCID()
	if err != nil {
		t.Fatalf("parse record root: %v", err)
	}
	if err := ValidateSignedRecord(record, RecordValidation{
		ExpectedName: signer.Name(),
		ExpectedRoot: recordRoot,
		Now:          clock.Now(),
		Policy:       config.RecordPolicy,
		PublicKey:    signer.GetPublic(),
	}); err != nil {
		t.Fatalf("validate canary record: %v", err)
	}
	if !strings.HasPrefix(record.Value, "/ipfs/") {
		t.Fatalf("record value is not an IPFS path: %s", record.Value)
	}
	if record.Sequence != 1 {
		t.Fatalf("canary record sequence = %d, want 1", record.Sequence)
	}
	if record.Format != SignedRecordBoundaryV1 {
		t.Fatalf("canary record format = %s, want %s", record.Format, SignedRecordBoundaryV1)
	}
}

func TestP2_04_CanaryRollbackReplay(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	signer := newTestSigner(t)
	node := newFakeKuboNode(config, signer)
	store := newMemoryPublicationStore()
	clock := &fakeClock{
		now: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC),
	}
	publisher, err := NewPublisher(node, signer, store, config.RecordPolicy, clock)
	if err != nil {
		t.Fatalf("create publisher: %v", err)
	}
	r1, err := publisher.Publish(context.Background(), testPublication(t, signer, 1, "rollback-canary"))
	if err != nil {
		t.Fatalf("first publish: %v", err)
	}
	r2, err := publisher.Publish(context.Background(), testPublication(t, signer, 2, "rollback-canary-2"))
	if err != nil {
		t.Fatalf("second publish: %v", err)
	}
	if r2.IPNSSequence != 2 {
		t.Fatalf("second sequence = %d, want 2", r2.IPNSSequence)
	}
	_, err = publisher.Publish(context.Background(), testPublication(t, signer, 1, "rollback-older"))
	if !errors.Is(err, ErrTrustRevisionRollback) {
		t.Fatalf("rollback error = %v, want ErrTrustRevisionRollback", err)
	}
	replayed, err := publisher.Publish(context.Background(), testPublication(t, signer, 2, "rollback-canary-2"))
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if replayed != r2 {
		t.Fatalf("replay receipt = %+v, want %+v", replayed, r2)
	}
	if len(node.records) != 2 {
		t.Fatalf("record count = %d, want 2 (no new records from rollback or replay)", len(node.records))
	}
	state, err := store.Load()
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if state.LastRootCID != r1.RootCID && state.LastRootCID != r2.RootCID {
		t.Fatalf("state root %s is neither first nor second", state.LastRootCID)
	}
	if state.LastSequence != 2 {
		t.Fatalf("state sequence = %d, want 2", state.LastSequence)
	}
}
