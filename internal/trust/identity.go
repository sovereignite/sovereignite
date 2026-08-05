// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

// Package trust owns Sovereignite SPIFFE identity, adoption, ownership,
// certificate, revocation, federation, and public trust-state publication.
package trust

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/ipfs/go-cid"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multibase"

	sovereignlibp2p "github.com/sovereignite/sovereignite/internal/libp2p"
)

const (
	// DeviceSPIFFEPathPrefix is the only SPIFFE subject namespace fixed by the
	// Phase 2 domain core. Additional subject namespaces require an authorized
	// certificate hierarchy and profile decision.
	DeviceSPIFFEPathPrefix = "/device/"

	maximumSPIFFEIDBytes = 2048
)

// DeviceIdentity is the immutable public binding between the canonical IPNS
// name, its canonical libp2p peer ID, and the corresponding SPIFFE ID.
type DeviceIdentity struct {
	CanonicalIPNS string `json:"canonical_ipns"`
	PeerID        string `json:"peer_id"`
	TrustDomain   string `json:"trust_domain"`
	SPIFFEID      string `json:"spiffe_id"`
}

// DeriveDeviceIdentity constructs the sole device SPIFFE form authorized by
// the bounded v5 interpretation:
//
//	spiffe://<canonical-IPNS-trust-domain>/device/<canonical-peer-id>
//
// The CIDv1/base36 IPNS name and peer ID must encode the same libp2p identity.
func DeriveDeviceIdentity(
	canonicalIPNS string,
	canonicalPeerID string,
) (DeviceIdentity, error) {
	trustDomain, keyCID, err := parseCanonicalIPNS(canonicalIPNS)
	if err != nil {
		return DeviceIdentity{}, err
	}
	peerID, err := peer.Decode(canonicalPeerID)
	if err != nil {
		return DeviceIdentity{}, fmt.Errorf("decode peer ID: %w", err)
	}
	if peerID.String() != canonicalPeerID {
		return DeviceIdentity{}, errors.New("peer ID is not in its canonical text form")
	}
	if !peer.ToCid(peerID).Equals(keyCID) {
		return DeviceIdentity{}, errors.New(
			"canonical IPNS identifier and peer ID represent different identities",
		)
	}

	spiffeID := (&url.URL{
		Scheme: "spiffe",
		Host:   trustDomain,
		Path:   DeviceSPIFFEPathPrefix + canonicalPeerID,
	}).String()
	if len(spiffeID) > maximumSPIFFEIDBytes {
		return DeviceIdentity{}, errors.New("device SPIFFE ID exceeds 2048 bytes")
	}
	return DeviceIdentity{
		CanonicalIPNS: canonicalIPNS,
		PeerID:        canonicalPeerID,
		TrustDomain:   trustDomain,
		SPIFFEID:      spiffeID,
	}, nil
}

// ParseDeviceSPIFFEID strictly parses the sole device subject namespace and
// proves that its trust domain and peer path encode the same identity.
func ParseDeviceSPIFFEID(raw string) (DeviceIdentity, error) {
	if raw == "" {
		return DeviceIdentity{}, errors.New("device SPIFFE ID is required")
	}
	if len(raw) > maximumSPIFFEIDBytes {
		return DeviceIdentity{}, errors.New("device SPIFFE ID exceeds 2048 bytes")
	}
	if strings.Contains(raw, "%") {
		return DeviceIdentity{}, errors.New("device SPIFFE ID must not use percent encoding")
	}
	id, err := url.Parse(raw)
	if err != nil {
		return DeviceIdentity{}, fmt.Errorf("parse device SPIFFE ID: %w", err)
	}
	if id.Scheme != "spiffe" ||
		id.Opaque != "" ||
		id.User != nil ||
		id.Host == "" ||
		id.RawPath != "" ||
		id.RawQuery != "" ||
		id.ForceQuery ||
		id.Fragment != "" ||
		id.RawFragment != "" {
		return DeviceIdentity{}, errors.New("device SPIFFE ID has an invalid URI form")
	}
	if !strings.HasPrefix(id.Path, DeviceSPIFFEPathPrefix) {
		return DeviceIdentity{}, errors.New("device SPIFFE ID has an unauthorized subject namespace")
	}
	peerText := strings.TrimPrefix(id.Path, DeviceSPIFFEPathPrefix)
	if peerText == "" || strings.Contains(peerText, "/") {
		return DeviceIdentity{}, errors.New("device SPIFFE ID must contain one peer ID path segment")
	}

	identity, err := DeriveDeviceIdentity(id.Host, peerText)
	if err != nil {
		return DeviceIdentity{}, err
	}
	if identity.SPIFFEID != raw {
		return DeviceIdentity{}, errors.New("device SPIFFE ID is not canonical")
	}
	return identity, nil
}

// TrustDomainFromIPNS validates and returns a canonical CIDv1/base36 IPNS
// identifier suitable for the SPIFFE trust-domain authority component.
func TrustDomainFromIPNS(canonicalIPNS string) (string, error) {
	trustDomain, _, err := parseCanonicalIPNS(canonicalIPNS)
	return trustDomain, err
}

func parseCanonicalIPNS(canonicalIPNS string) (string, cid.Cid, error) {
	if canonicalIPNS == "" {
		return "", cid.Undef, errors.New("canonical IPNS identifier is required")
	}
	if strings.TrimSpace(canonicalIPNS) != canonicalIPNS ||
		strings.HasPrefix(canonicalIPNS, "/ipns/") ||
		canonicalIPNS != strings.ToLower(canonicalIPNS) {
		return "", cid.Undef, errors.New(
			"IPNS identifier must be lowercase canonical text without an /ipns/ prefix",
		)
	}
	if err := sovereignlibp2p.ValidateHostnameLabel(canonicalIPNS); err != nil {
		return "", cid.Undef, fmt.Errorf("IPNS trust domain: %w", err)
	}
	keyCID, err := cid.Decode(canonicalIPNS)
	if err != nil {
		return "", cid.Undef, fmt.Errorf("decode canonical IPNS identifier: %w", err)
	}
	if keyCID.Version() != 1 || keyCID.Type() != cid.Libp2pKey {
		return "", cid.Undef, errors.New(
			"IPNS trust domain must be a CIDv1 libp2p-key identifier",
		)
	}
	reencoded, err := keyCID.StringOfBase(multibase.Base36)
	if err != nil {
		return "", cid.Undef, fmt.Errorf("encode canonical IPNS identifier: %w", err)
	}
	if reencoded != canonicalIPNS {
		return "", cid.Undef, errors.New("IPNS identifier is not canonical base36 CIDv1")
	}
	return canonicalIPNS, keyCID, nil
}
