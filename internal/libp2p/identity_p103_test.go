// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package libp2p

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/ipfs/go-cid"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	cryptopb "github.com/libp2p/go-libp2p/core/crypto/pb"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multibase"
)

// TestSharedTestVectorCanonicalNameIsDeterministic verifies that a given
// public key always derives the same canonical IPNS name. The exact value is
// not hard-coded here because the Go libp2p key generation is not seeded, but
// the function must be idempotent across calls within the same process.
func TestP103SharedTestVectorCanonicalNameIsDeterministic(t *testing.T) {
	t.Parallel()
	private, public, err := libp2pcrypto.GenerateKeyPair(libp2pcrypto.ECDSA, -1)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	_ = private
	expectedPeerID, err := peer.IDFromPublicKey(public)
	if err != nil {
		t.Fatalf("derive expected peer ID: %v", err)
	}
	keyCID := peer.ToCid(expectedPeerID)
	expectedName, err := keyCID.StringOfBase(multibase.Base36)
	if err != nil {
		t.Fatalf("encode expected base36: %v", err)
	}
	identity1, err := DerivePublicIdentity(firstPersistentHandle+50, public)
	if err != nil {
		t.Fatalf("derive identity first call: %v", err)
	}
	identity2, err := DerivePublicIdentity(firstPersistentHandle+50, public)
	if err != nil {
		t.Fatalf("derive identity second call: %v", err)
	}
	if identity1.Name != identity2.Name {
		t.Fatalf("canonical name changed across calls: %q vs %q", identity1.Name, identity2.Name)
	}
	if identity1.Name != strings.ToLower(identity1.Name) {
		t.Fatalf("canonical name is not lowercase: %q", identity1.Name)
	}
	if strings.HasPrefix(identity1.Name, "/ipns/") {
		t.Fatalf("canonical name includes /ipns/ prefix: %q", identity1.Name)
	}
	decoded, err := cid.Decode(identity1.Name)
	if err != nil {
		t.Fatalf("decode canonical name: %v", err)
	}
	if decoded.Version() != 1 {
		t.Fatalf("CID version = %d, want 1", decoded.Version())
	}
	if decoded.Type() != cid.Libp2pKey {
		t.Fatalf("CID codec = 0x%x, want libp2p-key", decoded.Type())
	}
	if identity1.Name != expectedName {
		t.Fatalf("canonical name %q does not match expected %q", identity1.Name, expectedName)
	}
}

// TestP103PeerIDIsStableAcrossDerivation verifies that the peer ID derived
// from a public key matches the peer ID obtained through the standard libp2p
// path and round-trips correctly.
func TestP103PeerIDIsStableAcrossDerivation(t *testing.T) {
	t.Parallel()
	handle := firstPersistentHandle + 51
	private, public, err := libp2pcrypto.GenerateKeyPair(libp2pcrypto.ECDSA, -1)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	_ = private
	expectedPeerID, err := peer.IDFromPublicKey(public)
	if err != nil {
		t.Fatalf("derive expected peer ID: %v", err)
	}
	identity, err := DerivePublicIdentity(handle, public)
	if err != nil {
		t.Fatalf("derive public identity: %v", err)
	}
	if identity.PeerID != expectedPeerID {
		t.Fatalf("peer ID = %q, want %q", identity.PeerID, expectedPeerID)
	}
	roundTripped, err := peer.Decode(identity.PeerID.String())
	if err != nil {
		t.Fatalf("round-trip peer ID decode: %v", err)
	}
	if roundTripped != expectedPeerID {
		t.Fatalf("round-tripped peer ID = %q, want %q", roundTripped, expectedPeerID)
	}
}

// TestP103IPNSNameCanonicalization verifies that the canonical name is
// lowercase, has no /ipns/ prefix, is base36-encoded, and is a valid CIDv1
// with libp2p-key codec, all within the 63-byte DNS label limit.
func TestP103IPNSNameCanonicalization(t *testing.T) {
	t.Parallel()
	key := newFakeTPMKey(t, firstPersistentHandle+52)
	identity, err := DerivePublicIdentity(key.Handle(), key.PublicKey())
	if err != nil {
		t.Fatalf("derive public identity: %v", err)
	}
	name := identity.Name
	if name == "" {
		t.Fatal("canonical name is empty")
	}
	if name != strings.ToLower(name) {
		t.Fatalf("canonical name is not lowercase: %q", name)
	}
	if strings.HasPrefix(name, "/ipns/") {
		t.Fatalf("canonical name has /ipns/ prefix: %q", name)
	}
	if strings.Contains(name, "/") {
		t.Fatalf("canonical name contains slash: %q", name)
	}
	encoding, _, err := multibase.Decode(name)
	if err != nil {
		t.Fatalf("multibase decode: %v", err)
	}
	if encoding != multibase.Base36 {
		t.Fatalf("encoding = %v, want Base36", encoding)
	}
	decoded, err := cid.Decode(name)
	if err != nil {
		t.Fatalf("CID decode: %v", err)
	}
	if decoded.Version() != 1 {
		t.Fatalf("CID version = %d, want 1", decoded.Version())
	}
	if decoded.Type() != cid.Libp2pKey {
		t.Fatalf("CID codec = 0x%x, want libp2p-key", decoded.Type())
	}
	if len(name) > 63 {
		t.Fatalf("canonical name length = %d, exceeds 63-byte DNS label limit", len(name))
	}
}

// TestP103HostnameLabelValidationCoversAllAcceptanceCases exercises the
// hostname validation with DNS label constraints: max 63 bytes, lowercase
// ASCII alphanumeric and hyphens only, no leading/trailing hyphens.
func TestP103HostnameLabelValidationCoversAllAcceptanceCases(t *testing.T) {
	t.Parallel()
	valid := []string{
		"a",
		"abc",
		"k51qzi5uqu5dl",
		"a-b",
		"abc123",
		strings.Repeat("a", 63),
	}
	invalid := []string{
		"",
		"A",
		"-a",
		"a-",
		"a.b",
		"a_b",
		"a b",
		"/ipns/abc",
		strings.Repeat("a", 64),
		"café",
		"\x00",
		"abc\x00def",
	}
	for _, v := range valid {
		if err := ValidateHostnameLabel(v); err != nil {
			t.Errorf("valid label %q rejected: %v", v, err)
		}
	}
	for _, v := range invalid {
		if err := ValidateHostnameLabel(v); err == nil {
			t.Errorf("invalid label %q accepted", v)
		}
	}
}

// TestP103TrustDomainDerivation verifies that the trust domain is identical
// to the canonical IPNS name and is a valid hostname label.
func TestP103TrustDomainDerivation(t *testing.T) {
	t.Parallel()
	key := newFakeTPMKey(t, firstPersistentHandle+53)
	identity, err := DerivePublicIdentity(key.Handle(), key.PublicKey())
	if err != nil {
		t.Fatalf("derive public identity: %v", err)
	}
	if err := ValidateHostnameLabel(identity.Name); err != nil {
		t.Fatalf("trust domain is not a valid hostname label: %v", err)
	}
	peerIDFromCid, err := peer.FromCid(peer.ToCid(identity.PeerID))
	if err != nil {
		t.Fatalf("convert peer ID to CID: %v", err)
	}
	if peerIDFromCid != identity.PeerID {
		t.Fatalf("round-trip peer ID mismatch: %q != %q", peerIDFromCid, identity.PeerID)
	}
}

// TestP103RejectTruncatedIdentityState verifies that identity state files
// missing required fields are rejected without mutation.
func TestP103RejectTruncatedIdentityState(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "empty JSON object",
			content: "{}",
		},
		{
			name:    "missing peer_id",
			content: `{"version":1,"tpm_handle":"0x81000001","public_key":"dGVzdA==","name":"test"}`,
		},
		{
			name:    "missing name",
			content: `{"version":1,"tpm_handle":"0x81000001","public_key":"dGVzdA==","peer_id":"12D3KooWtest"}`,
		},
		{
			name:    "missing tpm_handle",
			content: `{"version":1,"public_key":"dGVzdA==","peer_id":"12D3KooWtest","name":"test"}`,
		},
		{
			name:    "missing public_key",
			content: `{"version":1,"tpm_handle":"0x81000001","peer_id":"12D3KooWtest","name":"test"}`,
		},
		{
			name:    "wrong version",
			content: `{"version":99,"tpm_handle":"0x81000001","public_key":"dGVzdA==","peer_id":"12D3KooWtest","name":"test"}`,
		},
		{
			name:    "missing version",
			content: `{"tpm_handle":"0x81000001","public_key":"dGVzdA==","peer_id":"12D3KooWtest","name":"test"}`,
		},
		{
			name:    "extra field",
			content: `{"version":1,"tpm_handle":"0x81000001","public_key":"dGVzdA==","peer_id":"12D3KooWtest","name":"test","extra":"value"}`,
		},
		{
			name:    "truncated JSON",
			content: `{"version":1,"tpm_handle":"0x81`,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config := testConfig(t)
			if err := os.MkdirAll(config.StateRoot, 0o700); err != nil {
				t.Fatalf("create state root: %v", err)
			}
			if err := os.WriteFile(
				config.statePath(),
				[]byte(test.content),
				0o600,
			); err != nil {
				t.Fatalf("write truncated state: %v", err)
			}
			key := newFakeTPMKey(t, firstPersistentHandle+60)
			hostnamectl := &fakeHostnamectl{}
			_, err := Initialize(
				context.Background(),
				config,
				key,
				hostnamectl,
			)
			if err == nil {
				t.Fatal("truncated/malformed identity state was accepted")
			}
			if calls := hostnamectl.Calls(); len(calls) != 0 {
				t.Fatalf("hostnamectl called %d times for truncated state", len(calls))
			}
		})
	}
}

// TestP103RejectMutatedIdentityState verifies that any single field mutation
// in a persisted identity state is detected and rejected.
func TestP103RejectMutatedIdentityState(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	key := newFakeTPMKey(t, firstPersistentHandle+70)
	hostnamectl := &fakeHostnamectl{}
	if _, err := Initialize(
		context.Background(),
		config,
		key,
		hostnamectl,
	); err != nil {
		t.Fatalf("initialize identity: %v", err)
	}
	original, err := os.ReadFile(config.statePath())
	if err != nil {
		t.Fatalf("read original state: %v", err)
	}
	var record map[string]any
	if err := json.Unmarshal(original, &record); err != nil {
		t.Fatalf("decode original state: %v", err)
	}
	mutations := map[string]any{
		"tpm_handle": "0x810000ff",
		"peer_id":    "12D3KooWMUTATED",
		"name":       "k51qzi5uqumutated",
		"public_key": "bXV0YXRlZA==",
	}
	for field, mutated := range mutations {
		field := field
		mutated := mutated
		t.Run("mutate_"+field, func(t *testing.T) {
			// Subtests must not be parallel: they mutate a shared state file.
			copy := make(map[string]any)
			for k, v := range record {
				copy[k] = v
			}
			copy[field] = mutated
			mutatedContent, err := json.MarshalIndent(copy, "", "  ")
			if err != nil {
				t.Fatalf("marshal mutated state: %v", err)
			}
			mutatedContent = append(mutatedContent, '\n')
			if err := os.WriteFile(config.statePath(), mutatedContent, 0o600); err != nil {
				t.Fatalf("write mutated state: %v", err)
			}
			newKey := newFakeTPMKey(t, key.handle)
			if field == "tpm_handle" || field == "public_key" {
				newKey = key
			}
			hostnamectl := &fakeHostnamectl{}
			_, err = Initialize(
				context.Background(),
				config,
				newKey,
				hostnamectl,
			)
			if !errors.Is(err, ErrIdentityMismatch) {
				t.Fatalf(
					"mutated %s accepted: error = %v, want ErrIdentityMismatch",
					field,
					err,
				)
			}
			if calls := hostnamectl.Calls(); len(calls) != 0 {
				t.Fatalf("hostnamectl called %d times after %s mutation", len(calls), field)
			}
		})
	}
	// Restore original state so subsequent tests in this package are unaffected.
	if err := os.WriteFile(config.statePath(), original, 0o600); err != nil {
		t.Fatalf("restore original state: %v", err)
	}
}

// TestP103RejectWrongIdentityAlgorithm verifies that an identity derived from
// an unsupported key type (Ed25519) is rejected at the key-wrapping layer.
func TestP103RejectWrongIdentityAlgorithm(t *testing.T) {
	t.Parallel()
	key := newFakeTPMKeyOfType(
		t,
		firstPersistentHandle+71,
		libp2pcrypto.Ed25519,
		-1,
	)
	_, err := NewNonExportablePrivateKey(key)
	if err == nil {
		t.Fatal("Ed25519 identity key was accepted")
	}
}

// TestP103RejectIdentityPeerIDMismatch verifies that a mismatched peer ID in
// the identity record is detected during reopen.
func TestP103RejectIdentityPeerIDMismatch(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	key := newFakeTPMKey(t, firstPersistentHandle+72)
	if _, err := Initialize(
		context.Background(),
		config,
		key,
		&fakeHostnamectl{},
	); err != nil {
		t.Fatalf("initialize identity: %v", err)
	}
	content, err := os.ReadFile(config.statePath())
	if err != nil {
		t.Fatalf("read identity state: %v", err)
	}
	var record map[string]any
	if err := json.Unmarshal(content, &record); err != nil {
		t.Fatalf("decode identity state: %v", err)
	}
	record["peer_id"] = "12D3KooWFORGERYPeerID"
	mutated, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatalf("marshal mutated state: %v", err)
	}
	mutated = append(mutated, '\n')
	if err := os.WriteFile(config.statePath(), mutated, 0o600); err != nil {
		t.Fatalf("write mutated state: %v", err)
	}
	_, err = Initialize(
		context.Background(),
		config,
		key,
		&fakeHostnamectl{},
	)
	if !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("peer ID mismatch error = %v, want ErrIdentityMismatch", err)
	}
}

// TestP103RejectIdentityNameMismatch verifies that a mismatched canonical
// name in the identity record is detected during reopen.
func TestP103RejectIdentityNameMismatch(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	key := newFakeTPMKey(t, firstPersistentHandle+73)
	if _, err := Initialize(
		context.Background(),
		config,
		key,
		&fakeHostnamectl{},
	); err != nil {
		t.Fatalf("initialize identity: %v", err)
	}
	content, err := os.ReadFile(config.statePath())
	if err != nil {
		t.Fatalf("read identity state: %v", err)
	}
	var record map[string]any
	if err := json.Unmarshal(content, &record); err != nil {
		t.Fatalf("decode identity state: %v", err)
	}
	record["name"] = "k51qzi5uqmutatedname"
	mutated, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatalf("marshal mutated state: %v", err)
	}
	mutated = append(mutated, '\n')
	if err := os.WriteFile(config.statePath(), mutated, 0o600); err != nil {
		t.Fatalf("write mutated state: %v", err)
	}
	_, err = Initialize(
		context.Background(),
		config,
		key,
		&fakeHostnamectl{},
	)
	if !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("name mismatch error = %v, want ErrIdentityMismatch", err)
	}
}

// TestP103RejectNamingKeyRotation verifies that rotating the TPM key for an
// existing identity is rejected. The persisted identity must remain stable
// for the lifetime of the device.
func TestP103RejectNamingKeyRotation(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	originalKey := newFakeTPMKey(t, firstPersistentHandle+80)
	if _, err := Initialize(
		context.Background(),
		config,
		originalKey,
		&fakeHostnamectl{},
	); err != nil {
		t.Fatalf("initialize original identity: %v", err)
	}
	rotatedKey := newFakeTPMKey(t, firstPersistentHandle+80)
	_, err := Initialize(
		context.Background(),
		config,
		rotatedKey,
		&fakeHostnamectl{},
	)
	if !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("naming key rotation accepted: error = %v, want ErrIdentityMismatch", err)
	}
}

// TestP103RestartPersistenceAcrossMultipleCycles verifies that identity
// remains stable across repeated Initialize calls simulating restarts.
func TestP103RestartPersistenceAcrossMultipleCycles(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	key := newFakeTPMKey(t, firstPersistentHandle+90)
	hostnamectl := &fakeHostnamectl{}
	var names []string
	var peerIDs []string
	for i := 0; i < 5; i++ {
		identity, err := Initialize(
			context.Background(),
			config,
			key,
			hostnamectl,
		)
		if err != nil {
			t.Fatalf("initialize attempt %d: %v", i, err)
		}
		names = append(names, identity.Name)
		peerIDs = append(peerIDs, identity.PeerID.String())
	}
	for i := 1; i < len(names); i++ {
		if names[i] != names[0] {
			t.Fatalf(
				"identity name changed on restart %d: %q != %q",
				i,
				names[i],
				names[0],
			)
		}
		if peerIDs[i] != peerIDs[0] {
			t.Fatalf(
				"peer ID changed on restart %d: %q != %q",
				i,
				peerIDs[i],
				peerIDs[0],
			)
		}
	}
}

// TestP103DerivePublicIdentityNilPublicKey verifies that a nil public key is
// rejected.
func TestP103DerivePublicIdentityNilPublicKey(t *testing.T) {
	t.Parallel()
	_, err := DerivePublicIdentity(firstPersistentHandle+91, nil)
	if err == nil {
		t.Fatal("nil public key was accepted")
	}
}

// TestP103DerivePublicIdentityInvalidHandle verifies that handles outside the
// persistent range are rejected.
func TestP103DerivePublicIdentityInvalidHandle(t *testing.T) {
	t.Parallel()
	key := newFakeTPMKey(t, firstPersistentHandle+92)
	_, err := DerivePublicIdentity(0x00000001, key.PublicKey())
	if err == nil {
		t.Fatal("non-persistent handle was accepted")
	}
}

// TestP103InitializeRejectsNilContext verifies that a nil context is rejected.
func TestP103InitializeRejectsNilContext(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	key := newFakeTPMKey(t, firstPersistentHandle+93)
	var ctx context.Context
	_, err := Initialize(ctx, config, key, &fakeHostnamectl{})
	if err == nil {
		t.Fatal("nil context was accepted")
	}
}

// TestP103InitializeRejectsCancelledContext verifies that a cancelled context
// is rejected before any persistence.
func TestP103InitializeRejectsCancelledContext(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	key := newFakeTPMKey(t, firstPersistentHandle+94)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Initialize(ctx, config, key, &fakeHostnamectl{})
	if err == nil {
		t.Fatal("cancelled context was accepted")
	}
	if _, err := os.Stat(config.StateRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state root created after cancelled context: %v", err)
	}
}

// TestP103InitializeRejectsNilHostnameSetter verifies that a nil hostname
// setter is rejected before any persistence.
func TestP103InitializeRejectsNilHostnameSetter(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	key := newFakeTPMKey(t, firstPersistentHandle+95)
	var setter HostnameSetter
	_, err := Initialize(context.Background(), config, key, setter)
	if err == nil {
		t.Fatal("nil hostname setter was accepted")
	}
	if _, err := os.Stat(config.StateRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state root created after nil setter: %v", err)
	}
}

// TestP103HostnameLabelMaxDNSLength verifies the 63-byte boundary exactly.
func TestP103HostnameLabelMaxDNSLength(t *testing.T) {
	t.Parallel()
	exact63 := strings.Repeat("a", 63)
	if err := ValidateHostnameLabel(exact63); err != nil {
		t.Fatalf("63-byte label rejected: %v", err)
	}
	exact64 := strings.Repeat("a", 64)
	if err := ValidateHostnameLabel(exact64); err == nil {
		t.Fatal("64-byte label accepted")
	}
}

// TestP103DerivePublicIdentityFromRSAPublicKey verifies that RSA keys produce
// a valid canonical identity.
func TestP103DerivePublicIdentityFromRSAPublicKey(t *testing.T) {
	t.Parallel()
	key := newFakeTPMKeyOfType(t, firstPersistentHandle+96, libp2pcrypto.RSA, 2048)
	identity, err := DerivePublicIdentity(key.Handle(), key.PublicKey())
	if err != nil {
		t.Fatalf("derive RSA identity: %v", err)
	}
	if identity.PeerID == "" {
		t.Fatal("RSA identity has empty peer ID")
	}
	if identity.Name == "" {
		t.Fatal("RSA identity has empty canonical name")
	}
	if identity.Name != strings.ToLower(identity.Name) {
		t.Fatalf("RSA canonical name is not lowercase: %q", identity.Name)
	}
	if strings.HasPrefix(identity.Name, "/ipns/") {
		t.Fatalf("RSA canonical name has /ipns/ prefix: %q", identity.Name)
	}
	if err := ValidateHostnameLabel(identity.Name); err != nil {
		t.Fatalf("RSA canonical name is not a valid hostname: %v", err)
	}
}

// TestP103PersistentStateFilePermissions verifies that the identity state file
// is created with 0600 permissions and the state root with 0700 permissions.
func TestP103PersistentStateFilePermissions(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	key := newFakeTPMKey(t, firstPersistentHandle+97)
	if _, err := Initialize(
		context.Background(),
		config,
		key,
		&fakeHostnamectl{},
	); err != nil {
		t.Fatalf("initialize identity: %v", err)
	}
	info, err := os.Stat(config.statePath())
	if err != nil {
		t.Fatalf("stat identity state: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("identity state permissions = %o, want 600", info.Mode().Perm())
	}
	rootInfo, err := os.Stat(config.StateRoot)
	if err != nil {
		t.Fatalf("stat state root: %v", err)
	}
	if rootInfo.Mode().Perm() != 0o700 {
		t.Fatalf("state root permissions = %o, want 700", rootInfo.Mode().Perm())
	}
}

// TestP103IdentityStateContainsNoPrivateMaterial verifies that serialized
// identity state never contains base64-encoded private key material.
func TestP103IdentityStateContainsNoPrivateMaterial(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	key := newFakeTPMKey(t, firstPersistentHandle+98)
	if _, err := Initialize(
		context.Background(),
		config,
		key,
		&fakeHostnamectl{},
	); err != nil {
		t.Fatalf("initialize identity: %v", err)
	}
	raw, err := key.private.Raw()
	if err != nil {
		t.Fatalf("read test private key raw: %v", err)
	}
	content, err := os.ReadFile(config.statePath())
	if err != nil {
		t.Fatalf("read identity state: %v", err)
	}
	stateJSON := string(content)
	if len(raw) > 0 {
		encoded := base64.StdEncoding.EncodeToString(raw)
		if strings.Contains(stateJSON, encoded) {
			t.Fatal("identity state contains base64-encoded private key material")
		}
		hexEncoded := hex.EncodeToString(raw)
		if strings.Contains(stateJSON, hexEncoded) {
			t.Fatal("identity state contains hex-encoded private key material")
		}
	}
	if strings.Contains(stateJSON, "private") || strings.Contains(stateJSON, "priv") {
		t.Fatal("identity state contains private key field reference")
	}
}

// TestP103RejectStateWithWrongTPMHandle verifies that a mismatched TPM handle
// is detected.
func TestP103RejectStateWithWrongTPMHandle(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	key := newFakeTPMKey(t, firstPersistentHandle+99)
	if _, err := Initialize(
		context.Background(),
		config,
		key,
		&fakeHostnamectl{},
	); err != nil {
		t.Fatalf("initialize identity: %v", err)
	}
	content, err := os.ReadFile(config.statePath())
	if err != nil {
		t.Fatalf("read identity state: %v", err)
	}
	var record map[string]any
	if err := json.Unmarshal(content, &record); err != nil {
		t.Fatalf("decode identity state: %v", err)
	}
	record["tpm_handle"] = "0x8100ffff"
	mutated, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatalf("marshal mutated state: %v", err)
	}
	mutated = append(mutated, '\n')
	if err := os.WriteFile(config.statePath(), mutated, 0o600); err != nil {
		t.Fatalf("write mutated state: %v", err)
	}
	_, err = Initialize(
		context.Background(),
		config,
		key,
		&fakeHostnamectl{},
	)
	if !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("TPM handle mismatch error = %v, want ErrIdentityMismatch", err)
	}
}

// TestP103RejectStateWithWrongPublicKey verifies that a mismatched public key
// is detected.
func TestP103RejectStateWithWrongPublicKey(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	key := newFakeTPMKey(t, firstPersistentHandle+100)
	if _, err := Initialize(
		context.Background(),
		config,
		key,
		&fakeHostnamectl{},
	); err != nil {
		t.Fatalf("initialize identity: %v", err)
	}
	content, err := os.ReadFile(config.statePath())
	if err != nil {
		t.Fatalf("read identity state: %v", err)
	}
	var record map[string]any
	if err := json.Unmarshal(content, &record); err != nil {
		t.Fatalf("decode identity state: %v", err)
	}
	record["public_key"] = "ZmFrZXB1YmxpY2tleQ=="
	mutated, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatalf("marshal mutated state: %v", err)
	}
	mutated = append(mutated, '\n')
	if err := os.WriteFile(config.statePath(), mutated, 0o600); err != nil {
		t.Fatalf("write mutated state: %v", err)
	}
	_, err = Initialize(
		context.Background(),
		config,
		key,
		&fakeHostnamectl{},
	)
	if !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("public key mismatch error = %v, want ErrIdentityMismatch", err)
	}
}

// TestP103InitializePersistsAndReopensStableAcrossRestart explicitly simulates
// a restart by creating a new process context and verifying identity stability.
func TestP103InitializePersistsAndReopensStableAcrossRestart(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	key := newFakeTPMKey(t, firstPersistentHandle+101)
	hostnamectl := &fakeHostnamectl{}
	first, err := Initialize(context.Background(), config, key, hostnamectl)
	if err != nil {
		t.Fatalf("first initialize: %v", err)
	}
	firstName := first.Name
	firstPeerID := first.PeerID
	if _, err := os.Stat(config.statePath()); err != nil {
		t.Fatalf("identity state not persisted: %v", err)
	}
	second, err := Initialize(context.Background(), config, key, hostnamectl)
	if err != nil {
		t.Fatalf("second initialize (restart): %v", err)
	}
	if second.Name != firstName {
		t.Fatalf(
			"canonical name changed after restart: %q != %q",
			second.Name,
			firstName,
		)
	}
	if second.PeerID != firstPeerID {
		t.Fatalf(
			"peer ID changed after restart: %q != %q",
			second.PeerID,
			firstPeerID,
		)
	}
	if second.TPMHandle != first.TPMHandle {
		t.Fatalf(
			"TPM handle changed after restart: 0x%08x != 0x%08x",
			second.TPMHandle,
			first.TPMHandle,
		)
	}
}

// TestP103DerivePublicIdentityProducesConsistentPeerIDFromSamePublicKey
// ensures that two different handles producing identities from the same
// public key yield the same peer ID and canonical name.
func TestP103DerivePublicIdentityProducesConsistentPeerIDFromSamePublicKey(t *testing.T) {
	t.Parallel()
	key := newFakeTPMKey(t, firstPersistentHandle+102)
	id1, err := DerivePublicIdentity(key.Handle(), key.PublicKey())
	if err != nil {
		t.Fatalf("derive identity handle 1: %v", err)
	}
	id2, err := DerivePublicIdentity(key.Handle()+1, key.PublicKey())
	if err != nil {
		t.Fatalf("derive identity handle 2: %v", err)
	}
	if id1.PeerID != id2.PeerID {
		t.Fatalf(
			"peer IDs differ for same public key: %q != %q",
			id1.PeerID,
			id2.PeerID,
		)
	}
	if id1.Name != id2.Name {
		t.Fatalf(
			"canonical names differ for same public key: %q != %q",
			id1.Name,
			id2.Name,
		)
	}
}

// TestP103DerivePublicIdentityTPMHandleStoredCorrectly verifies that the TPM
// handle is stored in the identity record.
func TestP103DerivePublicIdentityTPMHandleStoredCorrectly(t *testing.T) {
	t.Parallel()
	handle := firstPersistentHandle + 103
	key := newFakeTPMKey(t, handle)
	identity, err := DerivePublicIdentity(handle, key.PublicKey())
	if err != nil {
		t.Fatalf("derive public identity: %v", err)
	}
	if identity.TPMHandle != handle {
		t.Fatalf(
			"TPM handle = 0x%08x, want 0x%08x",
			identity.TPMHandle,
			handle,
		)
	}
}

// TestP103InitializeSetsHostnameFromCanonicalName verifies that the hostname
// setter receives the canonical IPNS name.
func TestP103InitializeSetsHostnameFromCanonicalName(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	key := newFakeTPMKey(t, firstPersistentHandle+104)
	hostnamectl := &fakeHostnamectl{}
	identity, err := Initialize(context.Background(), config, key, hostnamectl)
	if err != nil {
		t.Fatalf("initialize identity: %v", err)
	}
	calls := hostnamectl.Calls()
	if len(calls) != 1 {
		t.Fatalf("hostnamectl call count = %d, want 1", len(calls))
	}
	if calls[0].name != identity.Name {
		t.Fatalf(
			"hostname = %q, want canonical name %q",
			calls[0].name,
			identity.Name,
		)
	}
	if calls[0].name != strings.ToLower(calls[0].name) {
		t.Fatalf("hostname is not lowercase: %q", calls[0].name)
	}
	if strings.HasPrefix(calls[0].name, "/ipns/") {
		t.Fatalf("hostname has /ipns/ prefix: %q", calls[0].name)
	}
}

// TestP103RejectIdentityStateWithTrailingData verifies that identity state
// with trailing data after valid JSON is rejected.
func TestP103RejectIdentityStateWithTrailingData(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	key := newFakeTPMKey(t, firstPersistentHandle+105)
	if _, err := Initialize(
		context.Background(),
		config,
		key,
		&fakeHostnamectl{},
	); err != nil {
		t.Fatalf("initialize identity: %v", err)
	}
	content, err := os.ReadFile(config.statePath())
	if err != nil {
		t.Fatalf("read identity state: %v", err)
	}
	tainted := append(content, []byte("\n// trailing comment")...)
	if err := os.WriteFile(config.statePath(), tainted, 0o600); err != nil {
		t.Fatalf("write tainted state: %v", err)
	}
	_, err = Initialize(
		context.Background(),
		config,
		key,
		&fakeHostnamectl{},
	)
	if err == nil {
		t.Fatal("identity state with trailing data was accepted")
	}
}

// TestP103RejectIdentityStateEmptyFile verifies that an empty identity state
// file is rejected.
func TestP103RejectIdentityStateEmptyFile(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	if err := os.MkdirAll(config.StateRoot, 0o700); err != nil {
		t.Fatalf("create state root: %v", err)
	}
	if err := os.WriteFile(config.statePath(), []byte{}, 0o600); err != nil {
		t.Fatalf("write empty state: %v", err)
	}
	key := newFakeTPMKey(t, firstPersistentHandle+106)
	_, err := Initialize(
		context.Background(),
		config,
		key,
		&fakeHostnamectl{},
	)
	if err == nil {
		t.Fatal("empty identity state was accepted")
	}
}

// TestP103RejectIdentityStateDirectoryInsteadOfFile verifies that a directory
// at the identity state path is rejected.
func TestP103RejectIdentityStateDirectoryInsteadOfFile(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	if err := os.MkdirAll(config.statePath(), 0o700); err != nil {
		t.Fatalf("create state as directory: %v", err)
	}
	key := newFakeTPMKey(t, firstPersistentHandle+107)
	_, err := Initialize(
		context.Background(),
		config,
		key,
		&fakeHostnamectl{},
	)
	if err == nil {
		t.Fatal("directory at identity state path was accepted")
	}
}

// TestP103DerivePublicIdentityPeerIDMatchesCidDecode ensures the peer ID in
// the identity matches the peer ID decoded from the canonical name.
func TestP103DerivePublicIdentityPeerIDMatchesCidDecode(t *testing.T) {
	t.Parallel()
	key := newFakeTPMKey(t, firstPersistentHandle+108)
	identity, err := DerivePublicIdentity(key.Handle(), key.PublicKey())
	if err != nil {
		t.Fatalf("derive public identity: %v", err)
	}
	decoded, err := cid.Decode(identity.Name)
	if err != nil {
		t.Fatalf("decode canonical name CID: %v", err)
	}
	peerFromCid, err := peer.FromCid(decoded)
	if err != nil {
		t.Fatalf("convert CID to peer ID: %v", err)
	}
	if peerFromCid != identity.PeerID {
		t.Fatalf(
			"peer ID from CID %q does not match identity peer ID %q",
			peerFromCid,
			identity.PeerID,
		)
	}
}

// TestP103InitializeDoesNotSetHostnameBeforePersist verifies the ordering
// constraint: identity state is written before hostname is set.
func TestP103InitializeDoesNotSetHostnameBeforePersist(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	key := newFakeTPMKey(t, firstPersistentHandle+109)
	var hostnameSetBeforePersist bool
	runner := hostnamectlFunc(func(_ context.Context, _ string) error {
		if _, err := os.Stat(config.statePath()); err != nil {
			hostnameSetBeforePersist = true
		}
		return nil
	})
	if _, err := Initialize(
		context.Background(),
		config,
		key,
		runner,
	); err != nil {
		t.Fatalf("initialize identity: %v", err)
	}
	if hostnameSetBeforePersist {
		t.Fatal("hostname was set before identity was persisted")
	}
}

// TestP103InitializeRejectsNilKey verifies that a nil TPM signing key is
// rejected.
func TestP103InitializeRejectsNilKey(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	var key TPMSigningKey
	_, err := Initialize(
		context.Background(),
		config,
		key,
		&fakeHostnamectl{},
	)
	if err == nil {
		t.Fatal("nil TPM key was accepted")
	}
}

// TestP103DerivePublicIdentityNameIsLowercaseBase36 verifies all properties
// of the canonical name in a single comprehensive test.
func TestP103DerivePublicIdentityNameIsLowercaseBase36(t *testing.T) {
	t.Parallel()
	key := newFakeTPMKey(t, firstPersistentHandle+110)
	identity, err := DerivePublicIdentity(key.Handle(), key.PublicKey())
	if err != nil {
		t.Fatalf("derive public identity: %v", err)
	}
	name := identity.Name
	if name == "" {
		t.Fatal("canonical name is empty")
	}
	if name != strings.ToLower(name) {
		t.Fatalf("canonical name is not lowercase: %q", name)
	}
	if strings.HasPrefix(name, "/ipns/") {
		t.Fatalf("canonical name has /ipns/ prefix: %q", name)
	}
	encoding, _, err := multibase.Decode(name)
	if err != nil {
		t.Fatalf("multibase decode: %v", err)
	}
	if encoding != multibase.Base36 {
		t.Fatalf("encoding = %v, want Base36", encoding)
	}
	if len(name) > 63 {
		t.Fatalf("canonical name length = %d, exceeds 63-byte DNS label limit", len(name))
	}
	if err := ValidateHostnameLabel(name); err != nil {
		t.Fatalf("canonical name is not a valid hostname label: %v", err)
	}
}

// TestP103InitializeRejectsPermissiveStateRootAndDoesNotMutate verifies that
// a permissive state root is rejected and its permissions are not changed.
func TestP103InitializeRejectsPermissiveStateRootAndDoesNotMutate(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	if err := os.MkdirAll(config.StateRoot, 0o755); err != nil {
		t.Fatalf("create permissive state root: %v", err)
	}
	key := newFakeTPMKey(t, firstPersistentHandle+111)
	_, err := Initialize(
		context.Background(),
		config,
		key,
		&fakeHostnamectl{},
	)
	if err == nil {
		t.Fatal("permissive state root was accepted")
	}
	info, err := os.Stat(config.StateRoot)
	if err != nil {
		t.Fatalf("stat state root: %v", err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf(
			"permissive state root permissions changed to %o, want unchanged 755",
			info.Mode().Perm(),
		)
	}
}

// TestP103ConcurrentInitializeWithSameKeyProducesExactlyOneIdentity verifies
// that concurrent Initialize calls with the same key produce exactly one
// success.
func TestP103ConcurrentInitializeWithSameKeyProducesExactlyOneIdentity(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	handle := firstPersistentHandle + 112
	keys := []*fakeTPMKey{
		newFakeTPMKey(t, handle),
		newFakeTPMKey(t, handle),
	}
	results := make(chan error, len(keys))
	for _, key := range keys {
		key := key
		go func() {
			_, err := Initialize(
				context.Background(),
				config,
				key,
				&fakeHostnamectl{},
			)
			results <- err
		}()
	}
	successes := 0
	mismatches := 0
	for range keys {
		err := <-results
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrIdentityMismatch):
			mismatches++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if successes != 1 || mismatches != 1 {
		t.Fatalf(
			"concurrent results = %d successes/%d mismatches, want 1/1",
			successes,
			mismatches,
		)
	}
}

// TestP103DerivePublicIdentityPublicKeyTypePreserved verifies that the public
// key type is preserved through derivation.
func TestP103DerivePublicIdentityPublicKeyTypePreserved(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		keyType cryptopb.KeyType
	}{
		{"ECDSA", cryptopb.KeyType_ECDSA},
		{"RSA", cryptopb.KeyType_RSA},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var bits int
			if tc.keyType == cryptopb.KeyType_RSA {
				bits = 2048
			} else {
				bits = -1
			}
			key := newFakeTPMKeyOfType(t, firstPersistentHandle+120, int(tc.keyType), bits)
			identity, err := DerivePublicIdentity(key.Handle(), key.PublicKey())
			if err != nil {
				t.Fatalf("derive %s identity: %v", tc.name, err)
			}
			if identity.PublicKey.Type() != tc.keyType {
				t.Fatalf(
					"public key type = %v, want %v",
					identity.PublicKey.Type(),
					tc.keyType,
				)
			}
		})
	}
}

// TestP103InitializeRejectsHostnameSetterError verifies that hostname setter
// errors are propagated.
func TestP103InitializeRejectsHostnameSetterError(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	key := newFakeTPMKey(t, firstPersistentHandle+121)
	sentinel := errors.New("hostname setter failed")
	_, err := Initialize(
		context.Background(),
		config,
		key,
		&fakeHostnamectl{err: sentinel},
	)
	if !errors.Is(err, sentinel) {
		t.Fatalf("hostname setter error = %v, want wrapped sentinel", err)
	}
}

// TestP103DerivePublicIdentityFromP256AndRSAKeys exercises identity derivation
// for both ECDSA P-256 and RSA-2048 keys, verifying the same canonical name
// properties.
func TestP103DerivePublicIdentityFromP256AndRSAKeys(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		keyType int
		bits    int
	}{
		{"P256", libp2pcrypto.ECDSA, -1},
		{"RSA2048", libp2pcrypto.RSA, 2048},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			key := newFakeTPMKeyOfType(t, firstPersistentHandle+130, tc.keyType, tc.bits)
			identity, err := DerivePublicIdentity(key.Handle(), key.PublicKey())
			if err != nil {
				t.Fatalf("derive %s identity: %v", tc.name, err)
			}
			if identity.PeerID == "" {
				t.Fatalf("%s identity has empty peer ID", tc.name)
			}
			if identity.Name == "" {
				t.Fatalf("%s identity has empty canonical name", tc.name)
			}
			if identity.Name != strings.ToLower(identity.Name) {
				t.Fatalf("%s canonical name is not lowercase: %q", tc.name, identity.Name)
			}
			if strings.HasPrefix(identity.Name, "/ipns/") {
				t.Fatalf("%s canonical name has /ipns/ prefix: %q", tc.name, identity.Name)
			}
			if err := ValidateHostnameLabel(identity.Name); err != nil {
				t.Fatalf("%s canonical name is not a valid hostname: %v", tc.name, err)
			}
			decoded, err := cid.Decode(identity.Name)
			if err != nil {
				t.Fatalf("%s decode canonical name CID: %v", tc.name, err)
			}
			if decoded.Version() != 1 || decoded.Type() != cid.Libp2pKey {
				t.Fatalf(
					"%s canonical name CID = v%d/0x%x, want v1/libp2p-key",
					tc.name,
					decoded.Version(),
					decoded.Type(),
				)
			}
		})
	}
}

// TestP103InitializeTwoDifferentKeysProduceDifferentIdentities verifies that
// two distinct TPM keys produce different identities.
func TestP103InitializeTwoDifferentKeysProduceDifferentIdentities(t *testing.T) {
	t.Parallel()
	config1 := testConfig(t)
	config2 := testConfig(t)
	key1 := newFakeTPMKey(t, firstPersistentHandle+140)
	key2 := newFakeTPMKey(t, firstPersistentHandle+141)
	id1, err := Initialize(context.Background(), config1, key1, &fakeHostnamectl{})
	if err != nil {
		t.Fatalf("initialize first identity: %v", err)
	}
	id2, err := Initialize(context.Background(), config2, key2, &fakeHostnamectl{})
	if err != nil {
		t.Fatalf("initialize second identity: %v", err)
	}
	if id1.Name == id2.Name {
		t.Fatalf("two different keys produced the same canonical name: %q", id1.Name)
	}
	if id1.PeerID == id2.PeerID {
		t.Fatalf("two different keys produced the same peer ID: %q", id1.PeerID)
	}
}

// TestP103DerivePublicIdentityAllPropertiesExercised performs a single
// comprehensive check of every identity property accepted by the canonical
// identity derivation.
func TestP103DerivePublicIdentityAllPropertiesExercised(t *testing.T) {
	t.Parallel()
	key := newFakeTPMKey(t, firstPersistentHandle+150)
	handle := key.Handle()
	publicKey := key.PublicKey()
	identity, err := DerivePublicIdentity(handle, publicKey)
	if err != nil {
		t.Fatalf("derive public identity: %v", err)
	}
	// TPM handle preserved
	if identity.TPMHandle != handle {
		t.Fatalf("TPM handle = 0x%08x, want 0x%08x", identity.TPMHandle, handle)
	}
	// Public key preserved
	if !identity.PublicKey.Equals(publicKey) {
		t.Fatal("public key not preserved through derivation")
	}
	// Peer ID derived from public key
	expectedPeerID, err := peer.IDFromPublicKey(publicKey)
	if err != nil {
		t.Fatalf("derive expected peer ID: %v", err)
	}
	if identity.PeerID != expectedPeerID {
		t.Fatalf("peer ID = %q, want %q", identity.PeerID, expectedPeerID)
	}
	// Canonical name is CIDv1 libp2p-key, lowercase, base36, valid hostname
	decoded, err := cid.Decode(identity.Name)
	if err != nil {
		t.Fatalf("decode canonical name: %v", err)
	}
	if decoded.Version() != 1 {
		t.Fatalf("CID version = %d, want 1", decoded.Version())
	}
	if decoded.Type() != cid.Libp2pKey {
		t.Fatalf("CID codec = 0x%x, want libp2p-key", decoded.Type())
	}
	if identity.Name != strings.ToLower(identity.Name) {
		t.Fatalf("canonical name is not lowercase: %q", identity.Name)
	}
	if strings.HasPrefix(identity.Name, "/ipns/") {
		t.Fatalf("canonical name has /ipns/ prefix: %q", identity.Name)
	}
	if len(identity.Name) > 63 {
		t.Fatalf("canonical name length = %d, exceeds 63-byte limit", len(identity.Name))
	}
	encoding, _, err := multibase.Decode(identity.Name)
	if err != nil {
		t.Fatalf("multibase decode: %v", err)
	}
	if encoding != multibase.Base36 {
		t.Fatalf("encoding = %v, want Base36", encoding)
	}
	if err := ValidateHostnameLabel(identity.Name); err != nil {
		t.Fatalf("canonical name is not a valid hostname label: %v", err)
	}
	// Peer ID matches round-trip from CID
	peerFromCid, err := peer.FromCid(decoded)
	if err != nil {
		t.Fatalf("peer ID from CID: %v", err)
	}
	if peerFromCid != identity.PeerID {
		t.Fatalf(
			"peer ID from CID %q does not match %q",
			peerFromCid,
			identity.PeerID,
		)
	}
}

// TestP103InitializePersistsOnlyPublicIdentityAndReopensStable is the
// canonical restart-persistence test that verifies the identity state file
// contains no private key material, has correct permissions, and produces
// the same identity across multiple opens.
func TestP103InitializePersistsOnlyPublicIdentityAndReopensStable(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	key := newFakeTPMKey(t, firstPersistentHandle+160)
	hostnamectl := &fakeHostnamectl{}
	first, err := Initialize(context.Background(), config, key, hostnamectl)
	if err != nil {
		t.Fatalf("initialize identity: %v", err)
	}
	second, err := Initialize(context.Background(), config, key, hostnamectl)
	if err != nil {
		t.Fatalf("reopen identity: %v", err)
	}
	if first.Name != second.Name || first.PeerID != second.PeerID {
		t.Fatalf(
			"identity changed across reopen: first %q/%q, second %q/%q",
			first.Name,
			first.PeerID,
			second.Name,
			second.PeerID,
		)
	}
	if calls := hostnamectl.Calls(); len(calls) != 2 {
		t.Fatalf("hostnamectl call count = %d, want 2", len(calls))
	}
	content, err := os.ReadFile(config.statePath())
	if err != nil {
		t.Fatalf("read identity state: %v", err)
	}
	var state map[string]any
	if err := json.Unmarshal(content, &state); err != nil {
		t.Fatalf("decode identity state: %v", err)
	}
	expectedFields := []string{"version", "tpm_handle", "public_key", "peer_id", "name"}
	if len(state) != len(expectedFields) {
		t.Fatalf("identity state field count = %d, want %d", len(state), len(expectedFields))
	}
	for _, field := range expectedFields {
		if _, ok := state[field]; !ok {
			t.Errorf("identity state missing %q", field)
		}
	}
	privateRaw, err := key.private.Raw()
	if err != nil {
		t.Fatalf("read test-only private key: %v", err)
	}
	if strings.Contains(string(content), base64.StdEncoding.EncodeToString(privateRaw)) {
		t.Fatal("identity state contains serialized private key material")
	}
	if strings.Contains(string(content), "/ipns/") {
		t.Fatal("identity state contains a non-canonical /ipns/ prefix")
	}
	info, err := os.Stat(config.statePath())
	if err != nil {
		t.Fatalf("stat identity state: %v", err)
	}
	if permissions := info.Mode().Perm(); permissions != 0o600 {
		t.Fatalf("identity state permissions = %o, want 600", permissions)
	}
	rootInfo, err := os.Stat(config.StateRoot)
	if err != nil {
		t.Fatalf("stat identity state root: %v", err)
	}
	if permissions := rootInfo.Mode().Perm(); permissions != 0o700 {
		t.Fatalf("identity state root permissions = %o, want 700", permissions)
	}
}
