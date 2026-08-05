// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package libp2p

import (
	"errors"
	"testing"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

func TestNonExportablePrivateKeyAllowsPublicOperations(t *testing.T) {
	t.Parallel()
	tpmKey := newFakeTPMKey(t, firstPersistentHandle+1)
	privateKey, err := NewNonExportablePrivateKey(tpmKey)
	if err != nil {
		t.Fatalf("wrap TPM key: %v", err)
	}

	if raw, err := privateKey.Raw(); !errors.Is(err, ErrPrivateKeyExportProhibited) {
		t.Fatalf("Raw error = %v, want export-prohibited error", err)
	} else if raw != nil {
		t.Fatalf("Raw returned %d bytes, want nil", len(raw))
	}
	if marshaled, err := libp2pcrypto.MarshalPrivateKey(privateKey); !errors.Is(
		err,
		ErrPrivateKeyExportProhibited,
	) {
		t.Fatalf("MarshalPrivateKey error = %v, want export-prohibited error", err)
	} else if marshaled != nil {
		t.Fatalf("MarshalPrivateKey returned %d bytes, want nil", len(marshaled))
	}
	if _, err := libp2pcrypto.MarshalPublicKey(privateKey.GetPublic()); err != nil {
		t.Fatalf("MarshalPublicKey: %v", err)
	}
	fromPrivate, err := peer.IDFromPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("derive peer ID from adapter: %v", err)
	}
	fromPublic, err := peer.IDFromPublicKey(tpmKey.PublicKey())
	if err != nil {
		t.Fatalf("derive peer ID from public key: %v", err)
	}
	if fromPrivate != fromPublic {
		t.Fatalf("peer ID from private adapter = %q, want %q", fromPrivate, fromPublic)
	}

	payload := []byte("TPM-backed libp2p identity")
	signature, err := privateKey.Sign(payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	valid, err := privateKey.GetPublic().Verify(payload, signature)
	if err != nil {
		t.Fatalf("verify signature: %v", err)
	}
	if !valid {
		t.Fatal("signature made by private adapter did not verify")
	}
	if !privateKey.Equals(privateKey) {
		t.Fatal("private adapter does not equal itself")
	}
}

func TestNewNonExportablePrivateKeyRejectsNonPersistentHandle(t *testing.T) {
	t.Parallel()
	key := newFakeTPMKey(t, firstPersistentHandle-1)
	if _, err := NewNonExportablePrivateKey(key); err == nil {
		t.Fatal("non-persistent TPM handle was accepted")
	}
}

func TestNewNonExportablePrivateKeyRejectsNonTPMIdentityKeyType(t *testing.T) {
	t.Parallel()
	key := newFakeTPMKeyOfType(
		t,
		firstPersistentHandle+4,
		libp2pcrypto.Ed25519,
		-1,
	)
	if _, err := NewNonExportablePrivateKey(key); err == nil {
		t.Fatal("non-RSA/ECDSA identity key was accepted")
	}
}

func TestNonExportablePrivateKeyPropagatesSigningError(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("TPM unavailable")
	key := newFakeTPMKey(t, firstPersistentHandle+2)
	key.signError = sentinel
	privateKey, err := NewNonExportablePrivateKey(key)
	if err != nil {
		t.Fatalf("wrap TPM key: %v", err)
	}
	if _, err := privateKey.Sign([]byte("payload")); !errors.Is(err, sentinel) {
		t.Fatalf("sign error = %v, want wrapped TPM error", err)
	}
}

func TestNonExportablePrivateKeySupportsP256Signatures(t *testing.T) {
	t.Parallel()
	key := newFakeTPMKeyOfType(
		t,
		firstPersistentHandle+3,
		libp2pcrypto.ECDSA,
		-1,
	)
	privateKey, err := NewNonExportablePrivateKey(key)
	if err != nil {
		t.Fatalf("wrap P-256 TPM-compatible key: %v", err)
	}
	payload := []byte("P-256 TPM-backed libp2p identity")
	signature, err := privateKey.Sign(payload)
	if err != nil {
		t.Fatalf("sign with P-256 adapter: %v", err)
	}
	valid, err := privateKey.GetPublic().Verify(payload, signature)
	if err != nil {
		t.Fatalf("verify P-256 adapter signature: %v", err)
	}
	if !valid {
		t.Fatal("P-256 adapter signature did not verify")
	}
}

func TestNonExportablePrivateKeySupportsRSASignatures(t *testing.T) {
	t.Parallel()
	key := newFakeTPMKeyOfType(
		t,
		firstPersistentHandle+5,
		libp2pcrypto.RSA,
		2048,
	)
	privateKey, err := NewNonExportablePrivateKey(key)
	if err != nil {
		t.Fatalf("wrap RSA TPM-compatible key: %v", err)
	}
	payload := []byte("RSA TPM-backed libp2p identity")
	signature, err := privateKey.Sign(payload)
	if err != nil {
		t.Fatalf("sign with RSA adapter: %v", err)
	}
	valid, err := privateKey.GetPublic().Verify(payload, signature)
	if err != nil {
		t.Fatalf("verify RSA adapter signature: %v", err)
	}
	if !valid {
		t.Fatal("RSA adapter signature did not verify")
	}
}
