// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package trust

import (
	"strings"
	"testing"

	"github.com/multiformats/go-multibase"
)

func TestDeriveDeviceIdentityBindsCanonicalIPNSPeerAndSPIFFE(t *testing.T) {
	t.Parallel()

	identity, _ := testIdentity(t)
	if identity.TrustDomain != identity.CanonicalIPNS {
		t.Fatalf(
			"trust domain = %q, want canonical IPNS %q",
			identity.TrustDomain,
			identity.CanonicalIPNS,
		)
	}
	wantSPIFFE := "spiffe://" + identity.CanonicalIPNS +
		DeviceSPIFFEPathPrefix + identity.PeerID
	if identity.SPIFFEID != wantSPIFFE {
		t.Fatalf("SPIFFE ID = %q, want %q", identity.SPIFFEID, wantSPIFFE)
	}
	parsed, err := ParseDeviceSPIFFEID(identity.SPIFFEID)
	if err != nil {
		t.Fatal(err)
	}
	if parsed != identity {
		t.Fatalf("parsed identity = %#v, want %#v", parsed, identity)
	}
}

func TestDeriveDeviceIdentityRejectsAlternateAndMismatchedIdentity(t *testing.T) {
	t.Parallel()

	left, _ := testIdentity(t)
	right, _ := testIdentity(t)
	if _, err := DeriveDeviceIdentity(left.CanonicalIPNS, right.PeerID); err == nil {
		t.Fatal("DeriveDeviceIdentity accepted mismatched IPNS and peer identities")
	}

	_, keyCID, err := multibase.Decode(left.CanonicalIPNS)
	if err != nil {
		t.Fatal(err)
	}
	alternate, err := multibase.Encode(multibase.Base32, keyCID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := TrustDomainFromIPNS(alternate); err == nil {
		t.Fatal("TrustDomainFromIPNS accepted alternate base encoding")
	}
	if _, err := TrustDomainFromIPNS(
		strings.ToUpper(left.CanonicalIPNS),
	); err == nil {
		t.Fatal("TrustDomainFromIPNS accepted case mutation")
	}
	if _, err := TrustDomainFromIPNS("/ipns/" + left.CanonicalIPNS); err == nil {
		t.Fatal("TrustDomainFromIPNS accepted /ipns/ prefix")
	}
}

func TestParseDeviceSPIFFEIDRejectsUnplannedNamespacesAndURIFeatures(t *testing.T) {
	t.Parallel()

	identity, _ := testIdentity(t)
	tests := []string{
		"spiffe://" + identity.TrustDomain + "/workload/" + identity.PeerID,
		identity.SPIFFEID + "/extra",
		identity.SPIFFEID + "?role=owner",
		identity.SPIFFEID + "#fragment",
		strings.Replace(identity.SPIFFEID, "/device/", "/device/%2e/", 1),
	}
	for _, candidate := range tests {
		if _, err := ParseDeviceSPIFFEID(candidate); err == nil {
			t.Fatalf("ParseDeviceSPIFFEID(%q) succeeded", candidate)
		}
	}
}
