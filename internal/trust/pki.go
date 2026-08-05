// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package trust

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"time"

	"github.com/sovereignite/sovereignite/internal/keymanager"
)

const (
	profileDeviceCA         = "sovereignite-device-ca-v1"
	profileMTLSLeaf         = "sovereignite-mtls-leaf-v1"
	profileCrossCertificate = "sovereignite-federation-cross-certificate-v1"
)

// CertificateKeyManager is the narrow TPM-backed certificate boundary. The
// Trust service never receives a crypto.Signer or private-key bytes.
type CertificateKeyManager interface {
	Metadata(context.Context, keymanager.Role) (keymanager.KeyMetadata, error)
	IssueCertificate(context.Context, keymanager.CertificateRequest) ([]byte, error)
}

// FederationMaterial contains verified public remote CA input supplied by the
// unresolved authority-approved exchange. It contains no trust direction;
// direction remains an explicit policy grant and durable edge.
type FederationMaterial struct {
	RemoteCACertificateDER []byte
	SourceGeneration       uint64
}

// FederationMaterialProvider supplies remote public CA input without adding a
// public RPC or inferring discovery data as authorization.
type FederationMaterialProvider interface {
	Fetch(
		context.Context,
		DeviceIdentity,
		string,
		VerifiedMTLSPeer,
	) (FederationMaterial, error)
}

// FederationMaterialProviderFunc adapts a function to the public-material
// provider seam.
type FederationMaterialProviderFunc func(
	context.Context,
	DeviceIdentity,
	string,
	VerifiedMTLSPeer,
) (FederationMaterial, error)

// Fetch implements FederationMaterialProvider.
func (f FederationMaterialProviderFunc) Fetch(
	ctx context.Context,
	local DeviceIdentity,
	remote string,
	peer VerifiedMTLSPeer,
) (FederationMaterial, error) {
	if f == nil {
		return FederationMaterial{}, errors.New(
			"federation public material provider is unavailable",
		)
	}
	return f(ctx, local, remote, peer)
}

func caPublicKey(
	ctx context.Context,
	manager CertificateKeyManager,
) (crypto.PublicKey, error) {
	if isNil(manager) {
		return nil, errors.New("TPM-backed certificate key manager is unavailable")
	}
	metadata, err := manager.Metadata(ctx, keymanager.RoleDeviceRootCA)
	if err != nil {
		return nil, fmt.Errorf("load TPM CA public metadata: %w", err)
	}
	if metadata.Role != keymanager.RoleDeviceRootCA ||
		metadata.Purpose != keymanager.PurposeCertificateAuthority ||
		len(metadata.PublicKeyDER) == 0 {
		return nil, errors.New("TPM CA public metadata has an invalid role or purpose")
	}
	publicKey, err := x509.ParsePKIXPublicKey(metadata.PublicKeyDER)
	if err != nil {
		return nil, fmt.Errorf("parse TPM CA public key: %w", err)
	}
	return publicKey, nil
}

func issueLocalCA(
	ctx context.Context,
	manager CertificateKeyManager,
	identity DeviceIdentity,
	serial *big.Int,
	notBefore time.Time,
	notAfter time.Time,
) ([]byte, error) {
	publicKey, err := caPublicKey(ctx, manager)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   identity.TrustDomain,
			Organization: []string{"Sovereignite"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign |
			x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		PublicKey:             publicKey,
	}
	encoded, err := manager.IssueCertificate(ctx, keymanager.CertificateRequest{
		Role:             keymanager.RoleDeviceRootCA,
		Profile:          profileDeviceCA,
		Template:         template,
		Parent:           template,
		SubjectPublicKey: publicKey,
	})
	if err != nil {
		return nil, fmt.Errorf("TPM-backed local CA issuance: %w", err)
	}
	certificate, err := x509.ParseCertificate(encoded)
	if err != nil {
		return nil, fmt.Errorf("parse issued local CA: %w", err)
	}
	if err := certificate.CheckSignatureFrom(certificate); err != nil {
		return nil, fmt.Errorf("verify issued local CA self-signature: %w", err)
	}
	if certificate.SerialNumber.Cmp(serial) != 0 ||
		!certificate.IsCA ||
		!certificate.BasicConstraintsValid ||
		certificate.KeyUsage&x509.KeyUsageCertSign == 0 ||
		certificate.Subject.String() != template.Subject.String() ||
		!samePublicKey(certificate.PublicKey, publicKey) {
		return nil, errors.New("issued local CA does not match the authorized template")
	}
	if certificate.NotBefore.Before(notBefore) ||
		certificate.NotAfter.After(notAfter) {
		return nil, errors.New("issued local CA validity exceeds its grant")
	}
	return encoded, nil
}

func issueMTLSLeaf(
	ctx context.Context,
	manager CertificateKeyManager,
	parent *x509.Certificate,
	identity DeviceIdentity,
	serial *big.Int,
	subjectPublicKey crypto.PublicKey,
	notBefore time.Time,
	notAfter time.Time,
) ([]byte, error) {
	spiffeURI, err := url.Parse(identity.SPIFFEID)
	if err != nil {
		return nil, fmt.Errorf("parse authorized SPIFFE ID: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: identity.SPIFFEID,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{spiffeURI},
	}
	encoded, err := manager.IssueCertificate(ctx, keymanager.CertificateRequest{
		Role:             keymanager.RoleDeviceRootCA,
		Profile:          profileMTLSLeaf,
		Template:         template,
		Parent:           parent,
		SubjectPublicKey: subjectPublicKey,
	})
	if err != nil {
		return nil, fmt.Errorf("TPM-backed mTLS certificate issuance: %w", err)
	}
	certificate, err := x509.ParseCertificate(encoded)
	if err != nil {
		return nil, fmt.Errorf("parse issued mTLS certificate: %w", err)
	}
	if err := validateIssuedMTLSCertificate(
		certificate,
		parent,
		identity,
		serial,
		subjectPublicKey,
		notBefore,
		notAfter,
	); err != nil {
		return nil, err
	}
	return encoded, nil
}

func issueCrossCertificate(
	ctx context.Context,
	manager CertificateKeyManager,
	parent *x509.Certificate,
	remote *x509.Certificate,
	serial *big.Int,
	notBefore time.Time,
	notAfter time.Time,
) ([]byte, error) {
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               remote.Subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign |
			x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          remote.SubjectKeyId,
	}
	encoded, err := manager.IssueCertificate(ctx, keymanager.CertificateRequest{
		Role:             keymanager.RoleDeviceRootCA,
		Profile:          profileCrossCertificate,
		Template:         template,
		Parent:           parent,
		SubjectPublicKey: remote.PublicKey,
	})
	if err != nil {
		return nil, fmt.Errorf("TPM-backed cross-certificate issuance: %w", err)
	}
	certificate, err := x509.ParseCertificate(encoded)
	if err != nil {
		return nil, fmt.Errorf("parse issued cross-certificate: %w", err)
	}
	if err := certificate.CheckSignatureFrom(parent); err != nil {
		return nil, fmt.Errorf("verify issued cross-certificate: %w", err)
	}
	if certificate.SerialNumber.Cmp(serial) != 0 ||
		!certificate.IsCA ||
		!certificate.BasicConstraintsValid ||
		certificate.MaxPathLen != 0 ||
		!certificate.MaxPathLenZero ||
		certificate.Subject.String() != remote.Subject.String() ||
		!samePublicKey(certificate.PublicKey, remote.PublicKey) {
		return nil, errors.New("issued cross-certificate does not match remote CA input")
	}
	if certificate.NotBefore.Before(notBefore) ||
		certificate.NotAfter.After(notAfter) {
		return nil, errors.New("issued cross-certificate validity exceeds its grant")
	}
	return encoded, nil
}

func validateIssuedMTLSCertificate(
	certificate *x509.Certificate,
	parent *x509.Certificate,
	identity DeviceIdentity,
	serial *big.Int,
	subjectPublicKey crypto.PublicKey,
	notBefore time.Time,
	notAfter time.Time,
) error {
	if err := certificate.CheckSignatureFrom(parent); err != nil {
		return fmt.Errorf("verify issued mTLS certificate: %w", err)
	}
	if certificate.SerialNumber.Cmp(serial) != 0 ||
		certificate.IsCA ||
		!certificate.BasicConstraintsValid ||
		certificate.KeyUsage != x509.KeyUsageDigitalSignature ||
		len(certificate.URIs) != 1 ||
		certificate.URIs[0] == nil ||
		certificate.URIs[0].String() != identity.SPIFFEID ||
		!samePublicKey(certificate.PublicKey, subjectPublicKey) {
		return errors.New("issued mTLS certificate does not match the authorized profile")
	}
	if len(certificate.ExtKeyUsage) != 2 ||
		!containsUsage(certificate.ExtKeyUsage, x509.ExtKeyUsageClientAuth) ||
		!containsUsage(certificate.ExtKeyUsage, x509.ExtKeyUsageServerAuth) ||
		len(certificate.UnknownExtKeyUsage) != 0 {
		return errors.New("issued mTLS certificate has invalid Extended Key Usage")
	}
	if certificate.NotBefore.Before(notBefore) ||
		certificate.NotAfter.After(notAfter) {
		return errors.New("issued mTLS certificate validity exceeds its grant")
	}
	return nil
}

func samePublicKey(left, right crypto.PublicKey) bool {
	leftDER, leftErr := x509.MarshalPKIXPublicKey(left)
	rightDER, rightErr := x509.MarshalPKIXPublicKey(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftDER, rightDER)
}

func containsUsage(usages []x509.ExtKeyUsage, expected x509.ExtKeyUsage) bool {
	for _, usage := range usages {
		if usage == expected {
			return true
		}
	}
	return false
}
