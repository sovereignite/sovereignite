// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package trust

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"time"
)

// VerifiedMTLSPeer is immutable evidence extracted from a TLS 1.3 connection
// whose client certificate has a verified chain. It intentionally contains no
// private key or authorization decision.
type VerifiedMTLSPeer struct {
	identity        DeviceIdentity
	certificateDER  []byte
	certificateHash [sha256.Size]byte
	publicKeyHash   [sha256.Size]byte
	notBefore       time.Time
	notAfter        time.Time
}

// Identity returns the authenticated canonical device identity.
func (p VerifiedMTLSPeer) Identity() DeviceIdentity {
	return p.identity
}

// CertificateDER returns a copy of the authenticated leaf certificate.
func (p VerifiedMTLSPeer) CertificateDER() []byte {
	return slices.Clone(p.certificateDER)
}

// CertificateSHA256 returns the authenticated leaf certificate fingerprint.
func (p VerifiedMTLSPeer) CertificateSHA256() [sha256.Size]byte {
	return p.certificateHash
}

// SubjectPublicKeySHA256 returns the leaf SubjectPublicKeyInfo fingerprint.
func (p VerifiedMTLSPeer) SubjectPublicKeySHA256() [sha256.Size]byte {
	return p.publicKeyHash
}

// NotBefore returns the authenticated leaf validity start.
func (p VerifiedMTLSPeer) NotBefore() time.Time {
	return p.notBefore
}

// NotAfter returns the authenticated leaf validity end.
func (p VerifiedMTLSPeer) NotAfter() time.Time {
	return p.notAfter
}

// VerifyMutualTLSPeer rejects plaintext, server-authentication-only, unverified,
// expired, CA, wrong-usage, or noncanonical peer certificates. First-trust
// authorization is a separate mandatory injected policy decision.
func VerifyMutualTLSPeer(
	state tls.ConnectionState,
	now time.Time,
) (VerifiedMTLSPeer, error) {
	if !state.HandshakeComplete {
		return VerifiedMTLSPeer{}, errors.New("mTLS handshake is incomplete")
	}
	if state.Version != tls.VersionTLS13 {
		return VerifiedMTLSPeer{}, errors.New("mTLS requires TLS 1.3")
	}
	if len(state.PeerCertificates) == 0 || state.PeerCertificates[0] == nil {
		return VerifiedMTLSPeer{}, errors.New("mTLS client certificate is required")
	}
	leaf := state.PeerCertificates[0]
	if !verifiedLeaf(leaf, state.VerifiedChains) {
		return VerifiedMTLSPeer{}, errors.New(
			"mTLS client certificate has no matching verified chain",
		)
	}
	if now.IsZero() {
		return VerifiedMTLSPeer{}, errors.New("verification time is required")
	}
	if now.Before(leaf.NotBefore) {
		return VerifiedMTLSPeer{}, errors.New("mTLS client certificate is not yet valid")
	}
	if now.After(leaf.NotAfter) {
		return VerifiedMTLSPeer{}, errors.New("mTLS client certificate is expired")
	}
	if !leaf.BasicConstraintsValid || leaf.IsCA {
		return VerifiedMTLSPeer{}, errors.New("mTLS peer certificate must be a leaf")
	}
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
		leaf.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != 0 {
		return VerifiedMTLSPeer{}, errors.New(
			"mTLS client certificate has invalid Key Usage",
		)
	}
	if !allowsClientAuthentication(leaf) {
		return VerifiedMTLSPeer{}, errors.New(
			"mTLS client certificate does not permit client authentication",
		)
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0] == nil {
		return VerifiedMTLSPeer{}, errors.New(
			"mTLS client certificate must contain exactly one URI SAN",
		)
	}
	identity, err := ParseDeviceSPIFFEID(leaf.URIs[0].String())
	if err != nil {
		return VerifiedMTLSPeer{}, fmt.Errorf("mTLS client SPIFFE ID: %w", err)
	}
	if len(leaf.Raw) == 0 || len(leaf.RawSubjectPublicKeyInfo) == 0 {
		return VerifiedMTLSPeer{}, errors.New(
			"mTLS client certificate is missing canonical DER",
		)
	}

	return VerifiedMTLSPeer{
		identity:        identity,
		certificateDER:  slices.Clone(leaf.Raw),
		certificateHash: sha256.Sum256(leaf.Raw),
		publicKeyHash:   sha256.Sum256(leaf.RawSubjectPublicKeyInfo),
		notBefore:       leaf.NotBefore.UTC(),
		notAfter:        leaf.NotAfter.UTC(),
	}, nil
}

func verifiedLeaf(
	leaf *x509.Certificate,
	chains [][]*x509.Certificate,
) bool {
	for _, chain := range chains {
		if len(chain) == 0 || chain[0] == nil {
			continue
		}
		valid := true
		for _, certificate := range chain {
			if certificate == nil {
				valid = false
				break
			}
		}
		if valid && bytes.Equal(leaf.Raw, chain[0].Raw) {
			return true
		}
	}
	return false
}

func allowsClientAuthentication(certificate *x509.Certificate) bool {
	if len(certificate.ExtKeyUsage) == 0 &&
		len(certificate.UnknownExtKeyUsage) == 0 {
		return true
	}
	for _, usage := range certificate.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth ||
			usage == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}
