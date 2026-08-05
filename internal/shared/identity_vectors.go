// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package shared

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"

	"github.com/ipfs/go-cid"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multibase"
)

// CanonicalTestVectorPublicKeyDER is the protobuf-marshaled Ed25519 public key
// for the canonical test vector. It is derived deterministically from a fixed
// seed and must never change.
//
// The raw 32-byte Ed25519 public key is:
//
//	d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
//
// The protobuf-marshaled form includes the libp2p key-type prefix.
var CanonicalTestVectorPublicKeyDER, _ = hex.DecodeString(
	"08011220d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
)

// CanonicalTestVectorPeerID is the libp2p peer ID derived from the canonical
// test vector public key.
const CanonicalTestVectorPeerID = "12D3KooWQK1wnefoLrcVHbbnf5tLzbopUd3K3bFAoJpA7YJgL5pV"

// CanonicalTestVectorIPNS is the canonical lowercase base36 CIDv1
// representation of the test vector identity, used as the IPNS name and
// SPIFFE trust-domain label. It must not contain an /ipns/ prefix.
const CanonicalTestVectorIPNS = "k51qzi5uqu5dljtg5upm7x7ugan9lql3ewyknv4r4mhhkwzn8n7cnbd1unfwgq"

// CanonicalTestVectorULA is the deterministic IPv6 unique-local /48 prefix
// derived from the canonical IPNS identifier via SHA-256 with domain separator
// per I-005.
const CanonicalTestVectorULA = "fde9:8410:6d44::/48"

// ValidateCanonicalTestVector verifies that the hardcoded public key bytes
// produce the expected peer ID, canonical IPNS name, and ULA prefix. It returns
// an error if any step of the derivation chain fails or produces an unexpected
// value.
func ValidateCanonicalTestVector() error {
	pubKey, err := libp2pcrypto.UnmarshalPublicKey(CanonicalTestVectorPublicKeyDER)
	if err != nil {
		return errors.New("unmarshal canonical test vector public key: " + err.Error())
	}

	peerID, err := peer.IDFromPublicKey(pubKey)
	if err != nil {
		return errors.New("derive peer ID: " + err.Error())
	}
	if peerID.String() != CanonicalTestVectorPeerID {
		return errors.New("peer ID mismatch: got " + peerID.String() + " want " + CanonicalTestVectorPeerID)
	}

	keyCID := peer.ToCid(peerID)
	name, err := keyCID.StringOfBase(multibase.Base36)
	if err != nil {
		return errors.New("encode CID as base36: " + err.Error())
	}
	if name != CanonicalTestVectorIPNS {
		return errors.New("canonical IPNS mismatch: got " + name + " want " + CanonicalTestVectorIPNS)
	}

	decoded, err := cid.Decode(name)
	if err != nil {
		return errors.New("decode canonical name CID: " + err.Error())
	}
	if decoded.Version() != 1 {
		return errors.New("CID version mismatch")
	}
	if decoded.Type() != cid.Libp2pKey {
		return errors.New("CID codec mismatch")
	}

	// Compute ULA exactly as ipfs.ULAForIPNSIdentifier does.
	cidBytes := decoded.Bytes()
	const domainSep = "github.com/sovereignite/sovereignite/ula/v1\x00"
	h := sha256.New()
	h.Write([]byte(domainSep))
	h.Write(cidBytes)
	sum := h.Sum(nil)

	var addr [16]byte
	addr[0] = 0xfd
	copy(addr[1:6], sum[:5])
	prefix := netip.PrefixFrom(netip.AddrFrom16(addr), 48)
	if prefix.String() != CanonicalTestVectorULA {
		return errors.New("ULA mismatch: got " + prefix.String() + " want " + CanonicalTestVectorULA)
	}

	return nil
}
