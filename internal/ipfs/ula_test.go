// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package ipfs

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"net/netip"
	"testing"

	"github.com/ipfs/go-cid"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/sovereignite/sovereignite/internal/shared"
)

func TestULAForIPNSIdentifierGolden(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		identifier string
		want       string
	}{
		{
			name:       "sha2-256 multihash",
			identifier: "1220000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			want:       "fd6e:c108:3ed3::/48",
		},
		{
			name:       "identity multihash",
			identifier: "002408011220000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			want:       "fd68:6208:a365::/48",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			identifier, err := hex.DecodeString(test.identifier)
			if err != nil {
				t.Fatalf("decode test identifier: %v", err)
			}
			got, err := ULAForIPNSIdentifier(identifier)
			if err != nil {
				t.Fatalf("map identifier: %v", err)
			}
			want := netip.MustParsePrefix(test.want)
			if got != want {
				t.Fatalf("prefix = %v, want %v", got, want)
			}
		})
	}
}

func TestULAForIPNSIdentifierRejectsEmptyInput(t *testing.T) {
	t.Parallel()

	for _, identifier := range [][]byte{nil, []byte{}} {
		if _, err := ULAForIPNSIdentifier(identifier); err == nil {
			t.Fatal("empty identifier was accepted")
		}
	}
}

func TestULAForIPNSIdentifierUsesCallerDecodedBytes(t *testing.T) {
	t.Parallel()

	fromHex, err := hex.DecodeString(
		"002408011220000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
	)
	if err != nil {
		t.Fatalf("decode hexadecimal identifier: %v", err)
	}
	fromBase64, err := base64.RawStdEncoding.DecodeString(
		"ACQIARIgAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
	)
	if err != nil {
		t.Fatalf("decode base64 identifier: %v", err)
	}
	if !bytes.Equal(fromHex, fromBase64) {
		t.Fatal("test encodings did not decode to identical identifier bytes")
	}

	hexPrefix, err := ULAForIPNSIdentifier(fromHex)
	if err != nil {
		t.Fatalf("map hexadecimal-decoded identifier: %v", err)
	}
	base64Prefix, err := ULAForIPNSIdentifier(fromBase64)
	if err != nil {
		t.Fatalf("map base64-decoded identifier: %v", err)
	}
	if hexPrefix != base64Prefix {
		t.Fatalf("equivalent decoded identifiers mapped to %v and %v", hexPrefix, base64Prefix)
	}
}

func TestULAForIPNSIdentifierPrefixBoundaries(t *testing.T) {
	t.Parallel()

	prefix, err := ULAForIPNSIdentifier([]byte{0x12, 0x20, 0x01})
	if err != nil {
		t.Fatalf("map identifier: %v", err)
	}
	if prefix.Bits() != 48 {
		t.Fatalf("prefix length = %d, want 48", prefix.Bits())
	}

	first := prefix.Addr().As16()
	if first[0] != 0xfd {
		t.Fatalf("first address byte = %#x, want 0xfd", first[0])
	}
	for index, value := range first[6:] {
		if value != 0 {
			t.Fatalf("address byte %d = %#x, want zero", index+6, value)
		}
	}

	last := first
	for index := 6; index < len(last); index++ {
		last[index] = 0xff
	}
	if !prefix.Contains(netip.AddrFrom16(first)) {
		t.Fatal("prefix does not contain its first address")
	}
	if !prefix.Contains(netip.AddrFrom16(last)) {
		t.Fatal("prefix does not contain its last address")
	}

	outside := first
	outside[5] ^= 0x01
	if prefix.Contains(netip.AddrFrom16(outside)) {
		t.Fatal("prefix contains an address outside its /48 boundary")
	}
}

func TestULAForIPNSIdentifierMutationChangesPrefix(t *testing.T) {
	t.Parallel()

	identifier := []byte{0x00, 0x24, 0x08, 0x01, 0x12, 0x20, 0xaa, 0xbb}
	before := bytes.Clone(identifier)
	original, err := ULAForIPNSIdentifier(identifier)
	if err != nil {
		t.Fatalf("map original identifier: %v", err)
	}

	mutated := bytes.Clone(identifier)
	mutated[len(mutated)-1] ^= 0x01
	changed, err := ULAForIPNSIdentifier(mutated)
	if err != nil {
		t.Fatalf("map mutated identifier: %v", err)
	}
	if original == changed {
		t.Fatalf("one-bit mutation retained prefix %v", original)
	}
	if !bytes.Equal(identifier, before) {
		t.Fatal("mapping mutated the caller's identifier bytes")
	}
}

func TestULAForIPNSIdentifierConcurrentDeterminism(t *testing.T) {
	t.Parallel()

	identifier := []byte{0x12, 0x20, 0xde, 0xad, 0xbe, 0xef}
	want, err := ULAForIPNSIdentifier(identifier)
	if err != nil {
		t.Fatalf("map identifier: %v", err)
	}

	const workers = 32
	results := make(chan netip.Prefix, workers)
	errors := make(chan error, workers)
	for range workers {
		go func() {
			prefix, mapErr := ULAForIPNSIdentifier(identifier)
			results <- prefix
			errors <- mapErr
		}()
	}

	for range workers {
		if err := <-errors; err != nil {
			t.Fatalf("concurrent mapping: %v", err)
		}
		if got := <-results; got != want {
			t.Fatalf("concurrent prefix = %v, want %v", got, want)
		}
	}
}

func TestCanonicalTestVectorULAConsistency(t *testing.T) {
	t.Parallel()

	if err := shared.ValidateCanonicalTestVector(); err != nil {
		t.Fatalf("shared canonical test vector invalid: %v", err)
	}

	// Decode the canonical IPNS name to binary CID bytes, then feed to
	// ULAForIPNSIdentifier to verify the ipfs package agrees with the shared
	// vector.
	decoded, err := cid.Decode(shared.CanonicalTestVectorIPNS)
	if err != nil {
		t.Fatalf("decode canonical IPNS name: %v", err)
	}
	peerID, err := peer.FromCid(decoded)
	if err != nil {
		t.Fatalf("extract peer ID from CID: %v", err)
	}
	if peerID.String() != shared.CanonicalTestVectorPeerID {
		t.Fatalf(
			"peer ID mismatch: got %q, want %q",
			peerID,
			shared.CanonicalTestVectorPeerID,
		)
	}

	prefix, err := ULAForIPNSIdentifier(decoded.Bytes())
	if err != nil {
		t.Fatalf("compute ULA: %v", err)
	}
	if prefix.String() != shared.CanonicalTestVectorULA {
		t.Fatalf(
			"ULA = %q, want %q",
			prefix,
			shared.CanonicalTestVectorULA,
		)
	}
}
