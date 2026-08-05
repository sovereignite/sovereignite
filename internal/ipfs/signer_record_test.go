// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package ipfs

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
)

func TestTPMIPNSSignerNeverExportsPrivateMaterial(t *testing.T) {
	t.Parallel()
	signer := newTestSigner(t)
	if encoded, err := signer.Raw(); encoded != nil ||
		!errors.Is(err, ErrPrivateKeyExportProhibited) {
		t.Fatalf("Raw = (%x, %v), want export denial", encoded, err)
	}
	if encoded, err := signer.Export(); encoded != nil ||
		!errors.Is(err, ErrPrivateKeyExportProhibited) {
		t.Fatalf("Export = (%x, %v), want export denial", encoded, err)
	}
	if encoded, err := libp2pcrypto.MarshalPrivateKey(signer); encoded != nil ||
		err == nil {
		t.Fatalf(
			"MarshalPrivateKey = (%x, %v), want export denial",
			encoded,
			err,
		)
	}
}

func TestTPMIPNSSignerConsumesCanonicalIdentityULA(t *testing.T) {
	t.Parallel()
	signer := newTestSigner(t)
	want, err := ULAForIPNSIdentifier(signer.CanonicalIdentifier())
	if err != nil {
		t.Fatalf("derive expected ULA: %v", err)
	}
	if got := signer.ULA(); got != want {
		t.Fatalf("signer ULA = %v, want %v", got, want)
	}
	if err := validateCanonicalIPNSName(signer.Name()); err != nil {
		t.Fatalf("signer IPNS name is not canonical: %v", err)
	}
	identifier := signer.CanonicalIdentifier()
	identifier[0] ^= 0xff
	if bytes.Equal(identifier, signer.CanonicalIdentifier()) {
		t.Fatal("canonical identifier was mutable through returned bytes")
	}
}

func TestTPMIPNSSignerRejectsMismatchedSignature(t *testing.T) {
	t.Parallel()
	firstPrivate, firstPublic, err := libp2pcrypto.GenerateKeyPair(
		libp2pcrypto.Ed25519,
		-1,
	)
	if err != nil {
		t.Fatalf("generate first key: %v", err)
	}
	secondPrivate, _, err := libp2pcrypto.GenerateKeyPair(
		libp2pcrypto.Ed25519,
		-1,
	)
	if err != nil {
		t.Fatalf("generate second key: %v", err)
	}
	signer, err := NewTPMIPNSSigner(&testTPMKey{
		handle:  0x81000041,
		private: secondPrivate,
		public:  firstPublic,
	})
	if err != nil {
		t.Fatalf("create mismatched signer seam: %v", err)
	}
	if _, err := signer.Sign([]byte("proof")); err == nil {
		t.Fatal("signature from a different key was accepted")
	}
	_ = firstPrivate
}

func TestSignedRecordValidatesSignatureFreshnessAndRollback(t *testing.T) {
	t.Parallel()
	signer := newTestSigner(t)
	root := testCID(t, []byte("complete immutable snapshot"))
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	policy := RecordPolicy{
		Validity:     time.Hour,
		MaxValidity:  time.Hour,
		MaxStaleness: 30 * time.Minute,
		ClockSkew:    time.Minute,
	}
	record, err := CreateSignedRecord(
		context.Background(),
		signer,
		root,
		7,
		now,
		policy,
	)
	if err != nil {
		t.Fatalf("create signed record: %v", err)
	}
	validate := func(
		input SignedRecord,
		validation RecordValidation,
		wantError bool,
	) {
		t.Helper()
		err := ValidateSignedRecord(input, validation)
		if wantError && err == nil {
			t.Fatal("invalid signed record was accepted")
		}
		if !wantError && err != nil {
			t.Fatalf("valid signed record was rejected: %v", err)
		}
	}
	base := RecordValidation{
		ExpectedName:     signer.Name(),
		ExpectedRoot:     root,
		PreviousSequence: 6,
		Now:              now,
		Policy:           policy,
		PublicKey:        signer.GetPublic(),
	}
	validate(record, base, false)

	rollback := base
	rollback.PreviousSequence = record.Sequence
	validate(record, rollback, true)

	expired := base
	expired.Now = record.ValidUntil
	validate(record, expired, true)

	stale := base
	stale.Now = record.IssuedAt.Add(31 * time.Minute)
	validate(record, stale, true)

	wrongRoot := base
	wrongRoot.ExpectedRoot = testCID(t, []byte("other snapshot"))
	validate(record, wrongRoot, true)

	wrongNameRecord := record.Clone()
	wrongNameRecord.Name = newTestSigner(t).Name()
	validate(wrongNameRecord, base, true)

	wrongCIDRecord := record.Clone()
	wrongCIDRecord.Value = "/ipfs/" +
		testCID(t, []byte("changed CID")).String()
	validate(wrongCIDRecord, base, true)

	tampered := record.Clone()
	tampered.Signature[0] ^= 0x01
	validate(tampered, base, true)

	tooLongPolicy := policy
	tooLongPolicy.Validity = 30 * time.Minute
	tooLongPolicy.MaxValidity = 30 * time.Minute
	tooLong := base
	tooLong.Policy = tooLongPolicy
	validate(record, tooLong, true)

	issuedInFuture, err := CreateSignedRecord(
		context.Background(),
		signer,
		root,
		8,
		now.Add(2*time.Minute),
		policy,
	)
	if err != nil {
		t.Fatalf("create future record: %v", err)
	}
	future := base
	future.PreviousSequence = 7
	validate(issuedInFuture, future, true)
}

func TestSignedRecordEnvelopeIsDeterministicAndPublic(t *testing.T) {
	t.Parallel()
	signer := newTestSigner(t)
	root := testCID(t, []byte("public root"))
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	policy := DefaultRecordPolicy()
	record, err := CreateSignedRecord(
		context.Background(),
		signer,
		root,
		1,
		now,
		policy,
	)
	if err != nil {
		t.Fatalf("create record: %v", err)
	}
	first, err := record.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	second, err := record.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal record again: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("signed record envelope is not deterministic")
	}
	if bytes.Contains(first, []byte("PRIVATE KEY")) {
		t.Fatal("signed record envelope contains private material")
	}
}
