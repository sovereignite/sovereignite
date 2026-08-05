// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

// Package mtls constructs TLS configurations that require mutually
// authenticated TLS 1.3 connections and verified SPIFFE identities.
package mtls

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const maximumSPIFFEIDLength = 2048

var (
	oidExtensionKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtensionSubjectAltName   = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidExtensionExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
)

// SPIFFEIDValidator applies the caller's authorization policy to a
// cryptographically verified peer SPIFFE ID. The URL is a private copy and may
// be retained by the validator.
type SPIFFEIDValidator func(*url.URL) error

// NewServerConfig constructs a TLS 1.3-only server configuration. It requires
// and verifies a client certificate against clientCAs, requires its SPIFFE ID
// to belong to clientTrustDomain, then calls validateClientID. clientCAs must
// contain only authorities trusted to issue identities in clientTrustDomain.
func NewServerConfig(
	certificate tls.Certificate,
	clientCAs *x509.CertPool,
	clientTrustDomain string,
	validateClientID SPIFFEIDValidator,
) (*tls.Config, error) {
	certificate, err := validateLocalCertificate(
		certificate,
		time.Now(),
		x509.ExtKeyUsageServerAuth,
	)
	if err != nil {
		return nil, fmt.Errorf("server certificate: %w", err)
	}
	clientCAs, err = cloneRequiredPool(clientCAs, "client CA")
	if err != nil {
		return nil, err
	}
	if !validTrustDomain(clientTrustDomain) {
		return nil, errors.New("client SPIFFE trust domain is invalid")
	}
	if validateClientID == nil {
		return nil, errors.New("client SPIFFE ID validator is required")
	}

	return &tls.Config{
		Certificates:     []tls.Certificate{certificate},
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		ClientAuth:       tls.RequireAndVerifyClientCert,
		ClientCAs:        clientCAs,
		VerifyConnection: verifySPIFFEConnection(
			clientTrustDomain,
			validateClientID,
		),
	}, nil
}

// NewClientConfig constructs a TLS 1.3-only client configuration. It presents
// certificate, verifies the server X.509 chain against roots, requires its
// SPIFFE ID to belong to serverTrustDomain, then calls validateServerID. roots
// must contain only authorities trusted to issue identities in
// serverTrustDomain.
//
// Go's built-in client verifier authenticates DNS and IP names, not URI SANs,
// so the returned configuration replaces that verifier with a complete X.509
// verification in VerifyConnection. InsecureSkipVerify disables only the
// built-in DNS/IP-name verifier; certificate verification is not skipped.
func NewClientConfig(
	certificate tls.Certificate,
	roots *x509.CertPool,
	serverTrustDomain string,
	validateServerID SPIFFEIDValidator,
) (*tls.Config, error) {
	certificate, err := validateLocalCertificate(
		certificate,
		time.Now(),
		x509.ExtKeyUsageClientAuth,
	)
	if err != nil {
		return nil, fmt.Errorf("client certificate: %w", err)
	}
	roots, err = cloneRequiredPool(roots, "root CA")
	if err != nil {
		return nil, err
	}
	if !validTrustDomain(serverTrustDomain) {
		return nil, errors.New("server SPIFFE trust domain is invalid")
	}
	if validateServerID == nil {
		return nil, errors.New("server SPIFFE ID validator is required")
	}
	verificationRoots := roots.Clone()

	return &tls.Config{
		Certificates:       []tls.Certificate{certificate},
		RootCAs:            roots,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // Verification is replaced in VerifyConnection.
		VerifyConnection: verifyServerSPIFFEConnection(
			verificationRoots,
			serverTrustDomain,
			validateServerID,
		),
	}, nil
}

func cloneRequiredPool(pool *x509.CertPool, name string) (*x509.CertPool, error) {
	if pool == nil {
		return nil, fmt.Errorf("%s pool is required", name)
	}
	if pool.Equal(x509.NewCertPool()) {
		return nil, fmt.Errorf("%s pool must not be empty", name)
	}
	return pool.Clone(), nil
}

func validateLocalCertificate(
	certificate tls.Certificate,
	now time.Time,
	requiredUsage x509.ExtKeyUsage,
) (tls.Certificate, error) {
	if len(certificate.Certificate) == 0 {
		return tls.Certificate{}, errors.New("certificate chain is required")
	}
	if certificate.PrivateKey == nil {
		return tls.Certificate{}, errors.New("private key is required")
	}

	parsed := make([]*x509.Certificate, len(certificate.Certificate))
	chain := make([][]byte, len(certificate.Certificate))
	for index, raw := range certificate.Certificate {
		if len(raw) == 0 {
			return tls.Certificate{}, fmt.Errorf("parse certificate chain entry %d: empty certificate", index)
		}
		chain[index] = bytes.Clone(raw)
		current, err := x509.ParseCertificate(chain[index])
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("parse certificate chain entry %d: %w", index, err)
		}
		if now.Before(current.NotBefore) {
			return tls.Certificate{}, fmt.Errorf("certificate chain entry %d is not yet valid", index)
		}
		if now.After(current.NotAfter) {
			return tls.Certificate{}, fmt.Errorf("certificate chain entry %d is expired", index)
		}
		parsed[index] = current
	}
	for index := 0; index+1 < len(parsed); index++ {
		if err := parsed[index].CheckSignatureFrom(parsed[index+1]); err != nil {
			return tls.Certificate{}, fmt.Errorf(
				"certificate chain entries %d and %d are not linked: %w",
				index,
				index+1,
				err,
			)
		}
	}

	signer, ok := certificate.PrivateKey.(crypto.Signer)
	if !ok {
		return tls.Certificate{}, errors.New("private key does not implement crypto.Signer")
	}
	certificatePublicKey, err := x509.MarshalPKIXPublicKey(parsed[0].PublicKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshal certificate public key: %w", err)
	}
	privatePublicKey, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshal private-key public key: %w", err)
	}
	if !bytes.Equal(certificatePublicKey, privatePublicKey) {
		return tls.Certificate{}, errors.New("certificate and private key do not match")
	}
	if _, err := spiffeID(parsed[0]); err != nil {
		return tls.Certificate{}, fmt.Errorf("leaf SPIFFE ID: %w", err)
	}
	if !allowsExtendedKeyUsage(parsed[0], requiredUsage) {
		return tls.Certificate{}, fmt.Errorf(
			"leaf certificate does not permit extended key usage %v",
			requiredUsage,
		)
	}

	certificate.Certificate = chain
	certificate.OCSPStaple = bytes.Clone(certificate.OCSPStaple)
	certificate.SignedCertificateTimestamps = cloneByteSlices(certificate.SignedCertificateTimestamps)
	certificate.Leaf = parsed[0]
	return certificate, nil
}

func cloneByteSlices(values [][]byte) [][]byte {
	if values == nil {
		return nil
	}
	cloned := make([][]byte, len(values))
	for index, value := range values {
		cloned[index] = bytes.Clone(value)
	}
	return cloned
}

func verifySPIFFEConnection(
	trustDomain string,
	validate SPIFFEIDValidator,
) func(tls.ConnectionState) error {
	return func(state tls.ConnectionState) error {
		leaf, err := requireTLS13Peer(state)
		if err != nil {
			return err
		}
		if !leafHasVerifiedChain(leaf, state.VerifiedChains) {
			return errors.New("mTLS peer certificate has no verified chain")
		}
		return validatePeerSPIFFEID(leaf, trustDomain, validate)
	}
}

func verifyServerSPIFFEConnection(
	roots *x509.CertPool,
	trustDomain string,
	validate SPIFFEIDValidator,
) func(tls.ConnectionState) error {
	return func(state tls.ConnectionState) error {
		leaf, err := requireTLS13Peer(state)
		if err != nil {
			return err
		}
		intermediates := x509.NewCertPool()
		for _, certificate := range state.PeerCertificates[1:] {
			if certificate == nil {
				return errors.New("mTLS peer certificate chain contains a nil certificate")
			}
			intermediates.AddCert(certificate)
		}
		verifiedChains, err := leaf.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			CurrentTime:   time.Now(),
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
		if err != nil {
			return fmt.Errorf("verify mTLS server certificate: %w", err)
		}
		if !leafHasVerifiedChain(leaf, verifiedChains) {
			return errors.New("mTLS server certificate has no verified chain")
		}
		return validatePeerSPIFFEID(leaf, trustDomain, validate)
	}
}

func requireTLS13Peer(state tls.ConnectionState) (*x509.Certificate, error) {
	if state.Version != tls.VersionTLS13 {
		return nil, errors.New("mTLS connection did not negotiate TLS 1.3")
	}
	if len(state.PeerCertificates) == 0 || state.PeerCertificates[0] == nil {
		return nil, errors.New("mTLS peer certificate is required")
	}
	return state.PeerCertificates[0], nil
}

func validatePeerSPIFFEID(
	leaf *x509.Certificate,
	trustDomain string,
	validate SPIFFEIDValidator,
) error {
	id, err := spiffeID(leaf)
	if err != nil {
		return fmt.Errorf("peer SPIFFE ID: %w", err)
	}
	if id.Host != trustDomain {
		return fmt.Errorf(
			"peer SPIFFE trust domain %q does not match %q",
			id.Host,
			trustDomain,
		)
	}
	if err := validate(id); err != nil {
		return fmt.Errorf("validate peer SPIFFE ID: %w", err)
	}
	return nil
}

func leafHasVerifiedChain(leaf *x509.Certificate, chains [][]*x509.Certificate) bool {
	for _, chain := range chains {
		if len(chain) > 0 &&
			chain[0] != nil &&
			bytes.Equal(chain[0].Raw, leaf.Raw) {
			return true
		}
	}
	return false
}

func spiffeID(certificate *x509.Certificate) (*url.URL, error) {
	if certificate == nil {
		return nil, errors.New("certificate is required")
	}
	if !certificate.BasicConstraintsValid ||
		certificate.IsCA {
		return nil, errors.New("SPIFFE identity certificate must be a leaf certificate")
	}
	if certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
		certificate.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != 0 {
		return nil, errors.New("SPIFFE identity certificate has invalid Key Usage")
	}
	if !hasCriticalExtension(certificate, oidExtensionKeyUsage) {
		return nil, errors.New("SPIFFE identity certificate Key Usage must be critical")
	}
	if !validSPIFFEExtendedKeyUsage(certificate) {
		return nil, errors.New("SPIFFE identity certificate has invalid Extended Key Usage")
	}
	if len(certificate.URIs) != 1 || certificate.URIs[0] == nil {
		return nil, errors.New("certificate must contain exactly one URI SAN")
	}

	rawID, err := rawURISAN(certificate)
	if err != nil {
		return nil, err
	}
	if len(rawID) > maximumSPIFFEIDLength {
		return nil, errors.New("SPIFFE ID exceeds 2048 bytes")
	}
	if strings.Contains(rawID, "#") {
		return nil, errors.New("SPIFFE ID must not contain a fragment")
	}
	id, err := url.Parse(rawID)
	if err != nil {
		return nil, fmt.Errorf("parse SPIFFE ID: %w", err)
	}
	if err := validateSPIFFEID(id); err != nil {
		return nil, err
	}
	return id, nil
}

func rawURISAN(certificate *x509.Certificate) (string, error) {
	var (
		foundSAN bool
		rawID    string
		uriCount int
	)
	for _, extension := range certificate.Extensions {
		if !extension.Id.Equal(oidExtensionSubjectAltName) {
			continue
		}
		if foundSAN {
			return "", errors.New("certificate contains multiple SAN extensions")
		}
		foundSAN = true

		var names []asn1.RawValue
		rest, err := asn1.Unmarshal(extension.Value, &names)
		if err != nil || len(rest) != 0 {
			return "", errors.New("certificate contains a malformed SAN extension")
		}
		for _, name := range names {
			if name.Class != asn1.ClassContextSpecific || name.Tag != 6 {
				continue
			}
			if name.IsCompound {
				return "", errors.New("certificate contains a malformed URI SAN")
			}
			for _, character := range name.Bytes {
				if character > 0x7f {
					return "", errors.New("certificate URI SAN must contain only ASCII")
				}
			}
			uriCount++
			rawID = string(name.Bytes)
		}
	}
	if !foundSAN || uriCount != 1 {
		return "", errors.New("certificate must contain exactly one URI SAN")
	}
	return rawID, nil
}

func hasCriticalExtension(
	certificate *x509.Certificate,
	oid asn1.ObjectIdentifier,
) bool {
	if certificate == nil {
		return false
	}
	count := 0
	critical := false
	for _, extension := range certificate.Extensions {
		if extension.Id.Equal(oid) {
			count++
			critical = extension.Critical
		}
	}
	return count == 1 && critical
}

func extensionCount(
	certificate *x509.Certificate,
	oid asn1.ObjectIdentifier,
) int {
	if certificate == nil {
		return 0
	}
	count := 0
	for _, extension := range certificate.Extensions {
		if extension.Id.Equal(oid) {
			count++
		}
	}
	return count
}

func validSPIFFEExtendedKeyUsage(certificate *x509.Certificate) bool {
	count := extensionCount(certificate, oidExtensionExtendedKeyUsage)
	if count == 0 {
		return true
	}
	if count != 1 ||
		len(certificate.ExtKeyUsage) != 2 ||
		len(certificate.UnknownExtKeyUsage) != 0 {
		return false
	}

	var clientAuth, serverAuth bool
	for _, usage := range certificate.ExtKeyUsage {
		switch usage {
		case x509.ExtKeyUsageClientAuth:
			clientAuth = true
		case x509.ExtKeyUsageServerAuth:
			serverAuth = true
		default:
			return false
		}
	}
	return clientAuth && serverAuth
}

func allowsExtendedKeyUsage(certificate *x509.Certificate, required x509.ExtKeyUsage) bool {
	if len(certificate.ExtKeyUsage) == 0 && len(certificate.UnknownExtKeyUsage) == 0 {
		return true
	}
	for _, usage := range certificate.ExtKeyUsage {
		if usage == required || usage == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

func validateSPIFFEID(id *url.URL) error {
	if id == nil {
		return errors.New("SPIFFE ID is required")
	}
	if len(id.String()) > maximumSPIFFEIDLength {
		return errors.New("SPIFFE ID exceeds 2048 bytes")
	}
	if id.Scheme != "spiffe" {
		return errors.New("SPIFFE ID scheme must be spiffe")
	}
	if id.Opaque != "" || id.User != nil {
		return errors.New("SPIFFE ID must use an authority without user information")
	}
	if id.Host == "" || !validTrustDomain(id.Host) {
		return errors.New("SPIFFE ID trust domain is invalid")
	}
	if id.RawQuery != "" || id.ForceQuery || id.Fragment != "" || id.RawFragment != "" {
		return errors.New("SPIFFE ID must not contain a query or fragment")
	}
	if !validSPIFFEPath(id) {
		return errors.New("SPIFFE ID path is invalid")
	}
	return nil
}

func validTrustDomain(trustDomain string) bool {
	if len(trustDomain) == 0 || len(trustDomain) > 255 {
		return false
	}
	for index := 0; index < len(trustDomain); index++ {
		character := trustDomain[index]
		if (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') ||
			character == '.' ||
			character == '-' ||
			character == '_' {
			continue
		}
		return false
	}
	return true
}

func validSPIFFEPath(id *url.URL) bool {
	if id.Path == "" ||
		!strings.HasPrefix(id.Path, "/") ||
		strings.HasSuffix(id.Path, "/") ||
		id.RawPath != "" ||
		strings.Contains(id.EscapedPath(), "%") {
		return false
	}
	for _, segment := range strings.Split(strings.TrimPrefix(id.Path, "/"), "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
		for index := 0; index < len(segment); index++ {
			character := segment[index]
			if (character >= 'a' && character <= 'z') ||
				(character >= 'A' && character <= 'Z') ||
				(character >= '0' && character <= '9') ||
				character == '.' ||
				character == '-' ||
				character == '_' {
				continue
			}
			return false
		}
	}
	return true
}
