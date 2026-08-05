// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package libp2p

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	cryptopb "github.com/libp2p/go-libp2p/core/crypto/pb"
	pb "github.com/sovereignite/sovereignite/pkg/api/proto/sovereignite/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

func TestGRPCGetIdentityReturnsCorrectIdentity(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	key := newFakeTPMKey(t, firstPersistentHandle+200)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	service, err := Start(
		ctx,
		config,
		key,
		&fakeHostLauncher{},
		&fakeHostnamectl{},
	)
	if err != nil {
		t.Fatalf("start identity service: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		_ = service.Close()
	})

	server := NewIdentityServer(service)
	resp, err := server.GetIdentity(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetIdentity: %v", err)
	}
	if resp.Identity == nil {
		t.Fatal("GetIdentity returned nil identity")
	}
	if resp.Identity.PeerId != service.Identity().PeerID.String() {
		t.Fatalf(
			"GetIdentity peer ID = %q, want %q",
			resp.Identity.PeerId,
			service.Identity().PeerID,
		)
	}
	if resp.Identity.Phase != pb.IdentityPhase_IDENTITY_PHASE_ACTIVE {
		t.Fatalf(
			"GetIdentity phase = %v, want ACTIVE",
			resp.Identity.Phase,
		)
	}
	if len(resp.Identity.PublicKeys) != 1 {
		t.Fatalf(
			"GetIdentity public key count = %d, want 1",
			len(resp.Identity.PublicKeys),
		)
	}
	pk := resp.Identity.PublicKeys[0]
	if pk.TpmHandle != "0x810000c8" {
		t.Fatalf(
			"GetIdentity TPM handle = %q, want 0x810000c8",
			pk.TpmHandle,
		)
	}
	expectedKeyType := mapKeyType(key.PublicKey().Type())
	if pk.Type != expectedKeyType {
		t.Fatalf(
			"GetIdentity key type = %v, want %v",
			pk.Type,
			expectedKeyType,
		)
	}
	rawBytes, err := libp2pcrypto.MarshalPublicKey(key.PublicKey())
	if err != nil {
		t.Fatalf("marshal expected public key: %v", err)
	}
	expectedBase64 := base64.StdEncoding.EncodeToString(rawBytes)
	if pk.PublicRawBase64 != expectedBase64 {
		t.Fatalf(
			"GetIdentity public key = %q, want %q",
			pk.PublicRawBase64,
			expectedBase64,
		)
	}
}

func TestGRPCGetTrustDomainReturnsCorrectTrustDomain(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	key := newFakeTPMKey(t, firstPersistentHandle+201)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	service, err := Start(
		ctx,
		config,
		key,
		&fakeHostLauncher{},
		&fakeHostnamectl{},
	)
	if err != nil {
		t.Fatalf("start identity service: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		_ = service.Close()
	})

	server := NewIdentityServer(service)
	resp, err := server.GetTrustDomain(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetTrustDomain: %v", err)
	}
	if resp.TrustDomain != service.Identity().Name {
		t.Fatalf(
			"GetTrustDomain = %q, want %q",
			resp.TrustDomain,
			service.Identity().Name,
		)
	}
}

func TestGRPCGetIdentityRejectsNilService(t *testing.T) {
	t.Parallel()
	server := &IdentityServer{service: nil}
	_, err := server.GetIdentity(context.Background(), &emptypb.Empty{})
	if code := status.Code(err); code != codes.Unavailable {
		t.Fatalf("GetIdentity status = %v, want Unavailable", code)
	}
}

func TestGRPCGetTrustDomainRejectsNilService(t *testing.T) {
	t.Parallel()
	server := &IdentityServer{service: nil}
	_, err := server.GetTrustDomain(context.Background(), &emptypb.Empty{})
	if code := status.Code(err); code != codes.Unavailable {
		t.Fatalf("GetTrustDomain status = %v, want Unavailable", code)
	}
}

func TestGRPCGetIdentityResponseContainsNoPrivateKeyMaterial(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	key := newFakeTPMKey(t, firstPersistentHandle+202)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	service, err := Start(
		ctx,
		config,
		key,
		&fakeHostLauncher{},
		&fakeHostnamectl{},
	)
	if err != nil {
		t.Fatalf("start identity service: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		_ = service.Close()
	})

	privateRaw, err := key.private.Raw()
	if err != nil {
		t.Fatalf("read test-only private key: %v", err)
	}
	privateKeyB64 := base64.StdEncoding.EncodeToString(privateRaw)

	server := NewIdentityServer(service)
	resp, err := server.GetIdentity(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetIdentity: %v", err)
	}
	respString := resp.String()
	if strings.Contains(respString, privateKeyB64) {
		t.Fatal("GetIdentity response contains serialized private key material")
	}
}

func TestGRPCGetTrustDomainResponseContainsNoPrivateKeyMaterial(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	key := newFakeTPMKey(t, firstPersistentHandle+203)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	service, err := Start(
		ctx,
		config,
		key,
		&fakeHostLauncher{},
		&fakeHostnamectl{},
	)
	if err != nil {
		t.Fatalf("start identity service: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		_ = service.Close()
	})

	privateRaw, err := key.private.Raw()
	if err != nil {
		t.Fatalf("read test-only private key: %v", err)
	}
	privateKeyB64 := base64.StdEncoding.EncodeToString(privateRaw)

	server := NewIdentityServer(service)
	resp, err := server.GetTrustDomain(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetTrustDomain: %v", err)
	}
	respString := resp.String()
	if strings.Contains(respString, privateKeyB64) {
		t.Fatal("GetTrustDomain response contains serialized private key material")
	}
}

func TestGRPCMapKeyTypeCoversAllSupportedTypes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input    cryptopb.KeyType
		expected pb.PublicKeyType
	}{
		{cryptopb.KeyType_RSA, pb.PublicKeyType_PUBLIC_KEY_TYPE_RSA},
		{cryptopb.KeyType_Ed25519, pb.PublicKeyType_PUBLIC_KEY_TYPE_ED25519},
		{cryptopb.KeyType_ECDSA, pb.PublicKeyType_PUBLIC_KEY_TYPE_ECDSA},
		{cryptopb.KeyType_Secp256k1, pb.PublicKeyType_PUBLIC_KEY_TYPE_SECP256K1},
		{cryptopb.KeyType(-99), pb.PublicKeyType_PUBLIC_KEY_TYPE_UNSPECIFIED},
	}
	for _, tc := range tests {
		got := mapKeyType(tc.input)
		if got != tc.expected {
			t.Errorf("mapKeyType(%v) = %v, want %v", tc.input, got, tc.expected)
		}
	}
}
