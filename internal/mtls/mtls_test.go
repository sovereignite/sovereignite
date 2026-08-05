// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package mtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testTLS12ServerName = "tls12.site.example"
	testTrustDomain     = "site.example"
)

type testAuthority struct {
	certificate *x509.Certificate
	der         []byte
	key         *ecdsa.PrivateKey
	pool        *x509.CertPool
}

type testLeafOptions struct {
	dnsNames             []string
	emptyExtKeyUsage     bool
	extKeyUsage          []x509.ExtKeyUsage
	nonCriticalKeyUsage  bool
	notAfter             time.Time
	notBefore            time.Time
	omitBasicConstraints bool
	rawURISAN            string
	spiffeIDs            []string
	unknownExtKeyUsage   []asn1.ObjectIdentifier
}

type testFixture struct {
	clientAuthority   *testAuthority
	clientCertificate tls.Certificate
	now               time.Time
	serverAuthority   *testAuthority
	serverCertificate tls.Certificate
}

type handshakeResult struct {
	client error
	server error
}

func TestConfigsEnforceStrictMutualTLS(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)

	serverConfig, err := NewServerConfig(
		fixture.serverCertificate,
		fixture.clientAuthority.pool,
		testTrustDomain,
		trustDomainValidator(testTrustDomain, nil),
	)
	if err != nil {
		t.Fatal(err)
	}
	clientConfig, err := NewClientConfig(
		fixture.clientCertificate,
		fixture.serverAuthority.pool,
		testTrustDomain,
		trustDomainValidator(testTrustDomain, nil),
	)
	if err != nil {
		t.Fatal(err)
	}

	if serverConfig.MinVersion != tls.VersionTLS13 ||
		serverConfig.MaxVersion != tls.VersionTLS13 {
		t.Fatalf(
			"server TLS versions = %x..%x, want TLS 1.3 only",
			serverConfig.MinVersion,
			serverConfig.MaxVersion,
		)
	}
	if clientConfig.MinVersion != tls.VersionTLS13 ||
		clientConfig.MaxVersion != tls.VersionTLS13 {
		t.Fatalf(
			"client TLS versions = %x..%x, want TLS 1.3 only",
			clientConfig.MinVersion,
			clientConfig.MaxVersion,
		)
	}
	if serverConfig.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("server ClientAuth = %v, want RequireAndVerifyClientCert", serverConfig.ClientAuth)
	}
	if serverConfig.ClientCAs == nil || clientConfig.RootCAs == nil {
		t.Fatal("explicit CA pools were not retained")
	}
	if serverConfig.VerifyConnection == nil || clientConfig.VerifyConnection == nil {
		t.Fatal("SPIFFE verification hook is missing")
	}
	if serverConfig.InsecureSkipVerify {
		t.Fatal("server must use Go's normal client-certificate verification")
	}
	if !clientConfig.InsecureSkipVerify {
		t.Fatal("client must replace DNS-name verification for URI-SAN authentication")
	}
	if len(serverConfig.Certificates) != 1 || len(clientConfig.Certificates) != 1 {
		t.Fatal("local certificate was not configured")
	}
}

func TestValidMutualTLSHandshake(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	var clientValidations atomic.Int32
	var serverValidations atomic.Int32

	serverConfig, err := NewServerConfig(
		fixture.serverCertificate,
		fixture.clientAuthority.pool,
		testTrustDomain,
		trustDomainValidator(testTrustDomain, &serverValidations),
	)
	if err != nil {
		t.Fatal(err)
	}
	clientConfig, err := NewClientConfig(
		fixture.clientCertificate,
		fixture.serverAuthority.pool,
		testTrustDomain,
		trustDomainValidator(testTrustDomain, &clientValidations),
	)
	if err != nil {
		t.Fatal(err)
	}

	result := runHandshake(t, serverConfig, clientConfig)
	if result.client != nil || result.server != nil {
		t.Fatalf("valid handshake failed: client=%v server=%v", result.client, result.server)
	}
	if clientValidations.Load() != 1 || serverValidations.Load() != 1 {
		t.Fatalf(
			"SPIFFE validator calls = client %d, server %d; want one each",
			clientValidations.Load(),
			serverValidations.Load(),
		)
	}
	if len(serverConfig.Certificates[0].Leaf.DNSNames) != 0 {
		t.Fatal("valid SPIFFE handshake unexpectedly depended on a DNS SAN")
	}
}

func TestServerRejectsAbsentClientCertificate(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	serverConfig := mustServerConfig(t, fixture)
	clientConfig, err := NewClientConfig(
		fixture.clientCertificate,
		fixture.serverAuthority.pool,
		testTrustDomain,
		trustDomainValidator(testTrustDomain, nil),
	)
	if err != nil {
		t.Fatal(err)
	}
	clientConfig.Certificates = nil

	result := runHandshake(t, serverConfig, clientConfig)
	if result.server == nil {
		t.Fatalf("server accepted a client without a certificate: client=%v", result.client)
	}
}

func TestMutualTLSRejectsUnknownCA(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	unknownAuthority := newTestAuthority(t, fixture.now, "unknown client CA")
	unknownClient := issueTestCertificate(t, unknownAuthority, testLeafOptions{
		notBefore: fixture.now.Add(-time.Hour),
		notAfter:  fixture.now.Add(time.Hour),
		spiffeIDs: []string{"spiffe://" + testTrustDomain + "/device/unknown"},
	})

	t.Run("client certificate", func(t *testing.T) {
		serverConfig := mustServerConfig(t, fixture)
		clientConfig, err := NewClientConfig(
			unknownClient,
			fixture.serverAuthority.pool,
			testTrustDomain,
			trustDomainValidator(testTrustDomain, nil),
		)
		if err != nil {
			t.Fatal(err)
		}
		clientConfig.GetClientCertificate = fixedClientCertificate(unknownClient)

		result := runHandshake(t, serverConfig, clientConfig)
		if result.server == nil {
			t.Fatalf("server accepted an unknown-CA client: client=%v", result.client)
		}
	})

	t.Run("server certificate", func(t *testing.T) {
		serverConfig := mustServerConfig(t, fixture)
		var validations atomic.Int32
		clientConfig, err := NewClientConfig(
			fixture.clientCertificate,
			unknownAuthority.pool,
			testTrustDomain,
			trustDomainValidator(testTrustDomain, &validations),
		)
		if err != nil {
			t.Fatal(err)
		}

		result := runHandshake(t, serverConfig, clientConfig)
		if result.client == nil {
			t.Fatalf("client accepted an unknown-CA server: server=%v", result.server)
		}
		if validations.Load() != 0 {
			t.Fatal("SPIFFE validator ran before X.509 chain verification")
		}
	})
}

func TestMutualTLSRejectsInvalidCertificateTimes(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	tests := []struct {
		name      string
		notBefore time.Time
		notAfter  time.Time
	}{
		{
			name:      "expired",
			notBefore: fixture.now.Add(-2 * time.Hour),
			notAfter:  fixture.now.Add(-time.Hour),
		},
		{
			name:      "not yet valid",
			notBefore: fixture.now.Add(time.Hour),
			notAfter:  fixture.now.Add(2 * time.Hour),
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			clientCertificate := issueTestCertificate(t, fixture.clientAuthority, testLeafOptions{
				notBefore: test.notBefore,
				notAfter:  test.notAfter,
				spiffeIDs: []string{"spiffe://" + testTrustDomain + "/device/invalid-time"},
			})
			if _, err := NewClientConfig(
				clientCertificate,
				fixture.serverAuthority.pool,
				testTrustDomain,
				trustDomainValidator(testTrustDomain, nil),
			); err == nil {
				t.Fatal("client configuration accepted a temporally invalid local certificate")
			}

			serverConfig := mustServerConfig(t, fixture)
			clientConfig := forcedClientConfig(clientCertificate, fixture.serverAuthority.pool)
			result := runHandshake(t, serverConfig, clientConfig)
			if result.server == nil {
				t.Fatalf(
					"server accepted a temporally invalid client certificate: client=%v",
					result.client,
				)
			}

			serverCertificate := issueTestCertificate(t, fixture.serverAuthority, testLeafOptions{
				notBefore: test.notBefore,
				notAfter:  test.notAfter,
				spiffeIDs: []string{"spiffe://" + testTrustDomain + "/service/invalid-time"},
			})
			if _, err := NewServerConfig(
				serverCertificate,
				fixture.clientAuthority.pool,
				testTrustDomain,
				trustDomainValidator(testTrustDomain, nil),
			); err == nil {
				t.Fatal("server configuration accepted a temporally invalid local certificate")
			}

			var validations atomic.Int32
			clientConfig, err := NewClientConfig(
				fixture.clientCertificate,
				fixture.serverAuthority.pool,
				testTrustDomain,
				trustDomainValidator(testTrustDomain, &validations),
			)
			if err != nil {
				t.Fatal(err)
			}
			result = runHandshake(
				t,
				rawServerConfig(serverCertificate, fixture.clientAuthority.pool),
				clientConfig,
			)
			if result.client == nil {
				t.Fatalf(
					"client accepted a temporally invalid server certificate: server=%v",
					result.server,
				)
			}
			if validations.Load() != 0 {
				t.Fatal("SPIFFE validator ran before server certificate time verification")
			}
		})
	}
}

func TestMutualTLSRejectsWrongSPIFFETrustDomain(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	wrongClient := issueTestCertificate(t, fixture.clientAuthority, testLeafOptions{
		notBefore: fixture.now.Add(-time.Hour),
		notAfter:  fixture.now.Add(time.Hour),
		spiffeIDs: []string{"spiffe://foreign.example/device/client"},
	})
	wrongServer := issueTestCertificate(t, fixture.serverAuthority, testLeafOptions{
		notBefore: fixture.now.Add(-time.Hour),
		notAfter:  fixture.now.Add(time.Hour),
		spiffeIDs: []string{"spiffe://foreign.example/service/server"},
	})

	t.Run("client identity", func(t *testing.T) {
		var validations atomic.Int32
		serverConfig, err := NewServerConfig(
			fixture.serverCertificate,
			fixture.clientAuthority.pool,
			testTrustDomain,
			func(*url.URL) error {
				validations.Add(1)
				return nil
			},
		)
		if err != nil {
			t.Fatal(err)
		}
		clientConfig, err := NewClientConfig(
			wrongClient,
			fixture.serverAuthority.pool,
			testTrustDomain,
			trustDomainValidator(testTrustDomain, nil),
		)
		if err != nil {
			t.Fatal(err)
		}

		result := runHandshake(t, serverConfig, clientConfig)
		if result.server == nil {
			t.Fatalf("server accepted a foreign trust domain: client=%v", result.client)
		}
		if validations.Load() != 0 {
			t.Fatal("server authorization hook ran before trust-domain enforcement")
		}
	})

	t.Run("server identity", func(t *testing.T) {
		serverConfig, err := NewServerConfig(
			wrongServer,
			fixture.clientAuthority.pool,
			testTrustDomain,
			trustDomainValidator(testTrustDomain, nil),
		)
		if err != nil {
			t.Fatal(err)
		}
		var validations atomic.Int32
		clientConfig, err := NewClientConfig(
			fixture.clientCertificate,
			fixture.serverAuthority.pool,
			testTrustDomain,
			func(*url.URL) error {
				validations.Add(1)
				return nil
			},
		)
		if err != nil {
			t.Fatal(err)
		}

		result := runHandshake(t, serverConfig, clientConfig)
		if result.client == nil {
			t.Fatalf("client accepted a foreign trust domain: server=%v", result.server)
		}
		if validations.Load() != 0 {
			t.Fatal("client authorization hook ran before trust-domain enforcement")
		}
	})
}

func TestConfigRejectsMalformedCertificateChain(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)

	t.Run("invalid DER", func(t *testing.T) {
		malformed := cloneTLSCertificate(fixture.clientCertificate)
		malformed.Certificate = append(malformed.Certificate, []byte("not a certificate"))
		if _, err := NewClientConfig(
			malformed,
			fixture.serverAuthority.pool,
			testTrustDomain,
			trustDomainValidator(testTrustDomain, nil),
		); err == nil {
			t.Fatal("configuration accepted malformed certificate DER")
		}
	})

	t.Run("unlinked chain", func(t *testing.T) {
		unrelatedAuthority := newTestAuthority(t, fixture.now, "unrelated CA")
		malformed := cloneTLSCertificate(fixture.clientCertificate)
		malformed.Certificate[1] = append([]byte(nil), unrelatedAuthority.der...)
		if _, err := NewClientConfig(
			malformed,
			fixture.serverAuthority.pool,
			testTrustDomain,
			trustDomainValidator(testTrustDomain, nil),
		); err == nil {
			t.Fatal("configuration accepted an unlinked certificate chain")
		}
	})

	t.Run("peer chain", func(t *testing.T) {
		malformed := cloneTLSCertificate(fixture.clientCertificate)
		malformed.Certificate = append(malformed.Certificate, []byte("not a certificate"))
		serverConfig := mustServerConfig(t, fixture)
		clientConfig := forcedClientConfig(malformed, fixture.serverAuthority.pool)

		result := runHandshake(t, serverConfig, clientConfig)
		if result.server == nil {
			t.Fatalf("server accepted a malformed peer certificate chain: client=%v", result.client)
		}
	})
}

func TestConfigRejectsCertificateKeyMismatch(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mismatched := cloneTLSCertificate(fixture.clientCertificate)
	mismatched.PrivateKey = otherKey

	if _, err := NewClientConfig(
		mismatched,
		fixture.serverAuthority.pool,
		testTrustDomain,
		trustDomainValidator(testTrustDomain, nil),
	); err == nil {
		t.Fatal("client configuration accepted a certificate/key mismatch")
	}
	if _, err := NewServerConfig(
		mismatched,
		fixture.clientAuthority.pool,
		testTrustDomain,
		trustDomainValidator(testTrustDomain, nil),
	); err == nil {
		t.Fatal("server configuration accepted a certificate/key mismatch")
	}
}

func TestMutualTLSRejectsWrongExtendedKeyUsage(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	serverOnlyClient := issueTestCertificate(t, fixture.clientAuthority, testLeafOptions{
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		notBefore:   fixture.now.Add(-time.Hour),
		notAfter:    fixture.now.Add(time.Hour),
		spiffeIDs:   []string{"spiffe://" + testTrustDomain + "/device/wrong-usage"},
	})
	clientOnlyServer := issueTestCertificate(t, fixture.serverAuthority, testLeafOptions{
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		notBefore:   fixture.now.Add(-time.Hour),
		notAfter:    fixture.now.Add(time.Hour),
		spiffeIDs:   []string{"spiffe://" + testTrustDomain + "/service/wrong-usage"},
	})
	unknownUsageClient := issueTestCertificate(t, fixture.clientAuthority, testLeafOptions{
		extKeyUsage:        []x509.ExtKeyUsage{},
		notBefore:         fixture.now.Add(-time.Hour),
		notAfter:          fixture.now.Add(time.Hour),
		spiffeIDs:         []string{"spiffe://" + testTrustDomain + "/device/unknown-usage"},
		unknownExtKeyUsage: []asn1.ObjectIdentifier{{1, 2, 3, 4}},
	})

	if _, err := NewClientConfig(
		serverOnlyClient,
		fixture.serverAuthority.pool,
		testTrustDomain,
		trustDomainValidator(testTrustDomain, nil),
	); err == nil {
		t.Fatal("client configuration accepted a local certificate without ClientAuth usage")
	}
	if _, err := NewServerConfig(
		clientOnlyServer,
		fixture.clientAuthority.pool,
		testTrustDomain,
		trustDomainValidator(testTrustDomain, nil),
	); err == nil {
		t.Fatal("server configuration accepted a local certificate without ServerAuth usage")
	}
	if _, err := NewClientConfig(
		unknownUsageClient,
		fixture.serverAuthority.pool,
		testTrustDomain,
		trustDomainValidator(testTrustDomain, nil),
	); err == nil {
		t.Fatal("client configuration accepted a certificate with only an unknown EKU")
	}

	t.Run("server certificate", func(t *testing.T) {
		var validations atomic.Int32
		clientConfig, err := NewClientConfig(
			fixture.clientCertificate,
			fixture.serverAuthority.pool,
			testTrustDomain,
			trustDomainValidator(testTrustDomain, &validations),
		)
		if err != nil {
			t.Fatal(err)
		}
		result := runHandshake(
			t,
			rawServerConfig(clientOnlyServer, fixture.clientAuthority.pool),
			clientConfig,
		)
		if result.client == nil {
			t.Fatalf("client accepted a server without ServerAuth usage: server=%v", result.server)
		}
		if validations.Load() != 0 {
			t.Fatal("SPIFFE validator ran before server EKU verification")
		}
	})

	t.Run("client certificate", func(t *testing.T) {
		result := runHandshake(
			t,
			mustServerConfig(t, fixture),
			forcedClientConfig(serverOnlyClient, fixture.serverAuthority.pool),
		)
		if result.server == nil {
			t.Fatalf("server accepted a client without ClientAuth usage: client=%v", result.client)
		}
	})
}

func TestConfigRejectsNonConformingSVIDExtensions(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	tests := []struct {
		name    string
		options testLeafOptions
	}{
		{
			name: "noncritical Key Usage",
			options: testLeafOptions{
				nonCriticalKeyUsage: true,
			},
		},
		{
			name: "empty Extended Key Usage",
			options: testLeafOptions{
				emptyExtKeyUsage: true,
			},
		},
		{
			name: "Any Extended Key Usage",
			options: testLeafOptions{
				extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			},
		},
		{
			name: "additional Extended Key Usage",
			options: testLeafOptions{
				extKeyUsage: []x509.ExtKeyUsage{
					x509.ExtKeyUsageServerAuth,
					x509.ExtKeyUsageClientAuth,
					x509.ExtKeyUsageCodeSigning,
				},
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			test.options.notBefore = fixture.now.Add(-time.Hour)
			test.options.notAfter = fixture.now.Add(time.Hour)
			test.options.spiffeIDs = []string{
				"spiffe://" + testTrustDomain + "/device/nonconforming",
			}
			certificate := issueTestCertificate(
				t,
				fixture.clientAuthority,
				test.options,
			)
			if _, err := NewClientConfig(
				certificate,
				fixture.serverAuthority.pool,
				testTrustDomain,
				trustDomainValidator(testTrustDomain, nil),
			); err == nil {
				t.Fatal("configuration accepted a nonconforming X509-SVID extension")
			}
		})
	}
}

func TestConfigAllowsAbsentExtendedKeyUsage(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	certificate := issueTestCertificate(t, fixture.clientAuthority, testLeafOptions{
		extKeyUsage: []x509.ExtKeyUsage{},
		notBefore:   fixture.now.Add(-time.Hour),
		notAfter:    fixture.now.Add(time.Hour),
		spiffeIDs:   []string{"spiffe://" + testTrustDomain + "/device/no-eku"},
	})

	if _, err := NewClientConfig(
		certificate,
		fixture.serverAuthority.pool,
		testTrustDomain,
		trustDomainValidator(testTrustDomain, nil),
	); err != nil {
		t.Fatalf("client configuration rejected an SVID without Extended Key Usage: %v", err)
	}
	if _, err := NewServerConfig(
		certificate,
		fixture.clientAuthority.pool,
		testTrustDomain,
		trustDomainValidator(testTrustDomain, nil),
	); err != nil {
		t.Fatalf("server configuration rejected an SVID without Extended Key Usage: %v", err)
	}
}

func TestConfigRejectsMissingLeafBasicConstraints(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	certificate := issueTestCertificate(t, fixture.clientAuthority, testLeafOptions{
		notBefore:             fixture.now.Add(-time.Hour),
		notAfter:              fixture.now.Add(time.Hour),
		omitBasicConstraints: true,
		spiffeIDs:             []string{"spiffe://" + testTrustDomain + "/device/no-constraints"},
	})

	if _, err := NewClientConfig(
		certificate,
		fixture.serverAuthority.pool,
		testTrustDomain,
		trustDomainValidator(testTrustDomain, nil),
	); err == nil {
		t.Fatal("client configuration accepted an SVID without Basic Constraints")
	}
	if _, err := NewServerConfig(
		certificate,
		fixture.clientAuthority.pool,
		testTrustDomain,
		trustDomainValidator(testTrustDomain, nil),
	); err == nil {
		t.Fatal("server configuration accepted an SVID without Basic Constraints")
	}
}

func TestConfigRejectsInvalidSecurityInputs(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	emptyPool := x509.NewCertPool()
	missingKey := cloneTLSCertificate(fixture.clientCertificate)
	missingKey.PrivateKey = nil

	tests := []struct {
		name  string
		build func() error
	}{
		{
			name: "server certificate",
			build: func() error {
				_, err := NewServerConfig(
					tls.Certificate{},
					fixture.clientAuthority.pool,
					testTrustDomain,
					trustDomainValidator(testTrustDomain, nil),
				)
				return err
			},
		},
		{
			name: "server private key",
			build: func() error {
				_, err := NewServerConfig(
					missingKey,
					fixture.clientAuthority.pool,
					testTrustDomain,
					trustDomainValidator(testTrustDomain, nil),
				)
				return err
			},
		},
		{
			name: "server client CA pool",
			build: func() error {
				_, err := NewServerConfig(
					fixture.serverCertificate,
					nil,
					testTrustDomain,
					trustDomainValidator(testTrustDomain, nil),
				)
				return err
			},
		},
		{
			name: "empty server client CA pool",
			build: func() error {
				_, err := NewServerConfig(
					fixture.serverCertificate,
					emptyPool,
					testTrustDomain,
					trustDomainValidator(testTrustDomain, nil),
				)
				return err
			},
		},
		{
			name: "server SPIFFE validator",
			build: func() error {
				_, err := NewServerConfig(
					fixture.serverCertificate,
					fixture.clientAuthority.pool,
					testTrustDomain,
					nil,
				)
				return err
			},
		},
		{
			name: "server client trust domain",
			build: func() error {
				_, err := NewServerConfig(
					fixture.serverCertificate,
					fixture.clientAuthority.pool,
					"",
					trustDomainValidator(testTrustDomain, nil),
				)
				return err
			},
		},
		{
			name: "client certificate",
			build: func() error {
				_, err := NewClientConfig(
					tls.Certificate{},
					fixture.serverAuthority.pool,
					testTrustDomain,
					trustDomainValidator(testTrustDomain, nil),
				)
				return err
			},
		},
		{
			name: "client root pool",
			build: func() error {
				_, err := NewClientConfig(
					fixture.clientCertificate,
					nil,
					testTrustDomain,
					trustDomainValidator(testTrustDomain, nil),
				)
				return err
			},
		},
		{
			name: "empty client root pool",
			build: func() error {
				_, err := NewClientConfig(
					fixture.clientCertificate,
					emptyPool,
					testTrustDomain,
					trustDomainValidator(testTrustDomain, nil),
				)
				return err
			},
		},
		{
			name: "client server trust domain",
			build: func() error {
				_, err := NewClientConfig(
					fixture.clientCertificate,
					fixture.serverAuthority.pool,
					"SITE.example",
					trustDomainValidator(testTrustDomain, nil),
				)
				return err
			},
		},
		{
			name: "client SPIFFE validator",
			build: func() error {
				_, err := NewClientConfig(
					fixture.clientCertificate,
					fixture.serverAuthority.pool,
					testTrustDomain,
					nil,
				)
				return err
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			if err := test.build(); err == nil {
				t.Fatal("configuration accepted an invalid or missing security input")
			}
		})
	}
}

func TestServerRejectsTLS12(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	serverCertificate := issueTestCertificate(t, fixture.serverAuthority, testLeafOptions{
		dnsNames:  []string{testTLS12ServerName},
		notBefore: fixture.now.Add(-time.Hour),
		notAfter:  fixture.now.Add(time.Hour),
		spiffeIDs: []string{"spiffe://" + testTrustDomain + "/service/tls12-probe"},
	})
	serverConfig, err := NewServerConfig(
		serverCertificate,
		fixture.clientAuthority.pool,
		testTrustDomain,
		trustDomainValidator(testTrustDomain, nil),
	)
	if err != nil {
		t.Fatal(err)
	}
	clientConfig := &tls.Config{
		Certificates: []tls.Certificate{fixture.clientCertificate},
		RootCAs:      fixture.serverAuthority.pool.Clone(),
		ServerName:   testTLS12ServerName,
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
	}

	result := runHandshake(t, serverConfig, clientConfig)
	if result.server == nil {
		t.Fatalf("server accepted TLS 1.2: client=%v", result.client)
	}
}

func TestServerRejectsPlaintext(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	serverConfig := mustServerConfig(t, fixture)
	serverNetwork, clientNetwork := net.Pipe()
	deadline := time.Now().Add(5 * time.Second)
	if err := serverNetwork.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := clientNetwork.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- tls.Server(serverNetwork, serverConfig).Handshake()
	}()

	if _, err := clientNetwork.Write([]byte("GET /")); err != nil {
		t.Fatal(err)
	}
	if err := clientNetwork.Close(); err != nil {
		t.Fatal(err)
	}
	serverError := <-serverErrors
	if err := serverNetwork.Close(); err != nil {
		t.Fatal(err)
	}
	if serverError == nil {
		t.Fatal("TLS server accepted plaintext")
	}
}

func TestSPIFFEIDValidationRejectsMalformedIdentities(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	tests := []struct {
		name   string
		rawURI string
		uris   []string
	}{
		{name: "missing URI SAN"},
		{
			name: "multiple URI SANs",
			uris: []string{
				"spiffe://site.example/device/one",
				"spiffe://site.example/device/two",
			},
		},
		{name: "wrong scheme", uris: []string{"https://site.example/device/one"}},
		{name: "uppercase trust domain", uris: []string{"spiffe://SITE.example/device/one"}},
		{name: "query", uris: []string{"spiffe://site.example/device/one?role=admin"}},
		{name: "empty query", uris: []string{"spiffe://site.example/device/one?"}},
		{name: "fragment", rawURI: "spiffe://site.example/device/one#admin"},
		{name: "empty fragment", rawURI: "spiffe://site.example/device/one#"},
		{name: "root identity", uris: []string{"spiffe://site.example"}},
		{name: "relative segment", uris: []string{"spiffe://site.example/device/../admin"}},
		{name: "encoded path", uris: []string{"spiffe://site.example/device/%61dmin"}},
		{
			name: "oversized trust domain",
			uris: []string{
				"spiffe://" + strings.Repeat("a", 256) + "/device/one",
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			issued := issueTestCertificate(t, fixture.clientAuthority, testLeafOptions{
				notBefore: fixture.now.Add(-time.Hour),
				notAfter:  fixture.now.Add(time.Hour),
				rawURISAN: test.rawURI,
				spiffeIDs: test.uris,
			})
			certificate, err := x509.ParseCertificate(issued.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			if _, err := spiffeID(certificate); err == nil {
				t.Fatal("accepted malformed SPIFFE identity")
			}
		})
	}
}

func newTestFixture(t *testing.T) testFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	serverAuthority := newTestAuthority(t, now, "server CA")
	clientAuthority := newTestAuthority(t, now, "client CA")
	return testFixture{
		clientAuthority:   clientAuthority,
		clientCertificate: issueTestCertificate(t, clientAuthority, testLeafOptions{
			notBefore: now.Add(-time.Hour),
			notAfter:  now.Add(time.Hour),
			spiffeIDs: []string{"spiffe://" + testTrustDomain + "/device/client"},
		}),
		now:               now,
		serverAuthority:   serverAuthority,
		serverCertificate: issueTestCertificate(t, serverAuthority, testLeafOptions{
			notBefore: now.Add(-time.Hour),
			notAfter:  now.Add(time.Hour),
			spiffeIDs: []string{"spiffe://" + testTrustDomain + "/service/server"},
		}),
	}
}

func newTestAuthority(t *testing.T, now time.Time, commonName string) *testAuthority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          randomSerialNumber(t),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(certificate)
	return &testAuthority{
		certificate: certificate,
		der:         der,
		key:         key,
		pool:        pool,
	}
}

func issueTestCertificate(
	t *testing.T,
	authority *testAuthority,
	options testLeafOptions,
) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	extendedKeyUsage := options.extKeyUsage
	if extendedKeyUsage == nil {
		extendedKeyUsage = []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		}
	}
	template := &x509.Certificate{
		SerialNumber:          randomSerialNumber(t),
		Subject:               pkix.Name{CommonName: "test identity"},
		NotBefore:             options.notBefore,
		NotAfter:              options.notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           append([]x509.ExtKeyUsage(nil), extendedKeyUsage...),
		DNSNames:              append([]string(nil), options.dnsNames...),
		BasicConstraintsValid: !options.omitBasicConstraints,
		UnknownExtKeyUsage:    append([]asn1.ObjectIdentifier(nil), options.unknownExtKeyUsage...),
	}
	if options.rawURISAN != "" {
		rawNames, err := asn1.Marshal([]asn1.RawValue{{
			Class: asn1.ClassContextSpecific,
			Tag:   6,
			Bytes: []byte(options.rawURISAN),
		}})
		if err != nil {
			t.Fatal(err)
		}
		template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
			Id:    oidExtensionSubjectAltName,
			Value: rawNames,
		})
	} else {
		for _, rawID := range options.spiffeIDs {
			id, err := url.Parse(rawID)
			if err != nil {
				t.Fatal(err)
			}
			template.URIs = append(template.URIs, id)
		}
	}
	if options.nonCriticalKeyUsage {
		keyUsage, err := asn1.Marshal(asn1.BitString{
			Bytes:     []byte{0x80},
			BitLength: 1,
		})
		if err != nil {
			t.Fatal(err)
		}
		template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
			Id:       oidExtensionKeyUsage,
			Critical: false,
			Value:    keyUsage,
		})
	}
	if options.emptyExtKeyUsage {
		emptySequence, err := asn1.Marshal([]asn1.ObjectIdentifier{})
		if err != nil {
			t.Fatal(err)
		}
		template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
			Id:    oidExtensionExtendedKeyUsage,
			Value: emptySequence,
		})
	}
	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		authority.certificate,
		&key.PublicKey,
		authority.key,
	)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der, append([]byte(nil), authority.der...)},
		PrivateKey:  key,
	}
}

func randomSerialNumber(t *testing.T) *big.Int {
	t.Helper()
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, limit)
	if err != nil {
		t.Fatal(err)
	}
	if serialNumber.Sign() == 0 {
		return big.NewInt(1)
	}
	return serialNumber
}

func trustDomainValidator(
	trustDomain string,
	calls *atomic.Int32,
) SPIFFEIDValidator {
	return func(id *url.URL) error {
		if id.Host != trustDomain {
			return fmt.Errorf("trust domain %q is not allowed", id.Host)
		}
		if calls != nil {
			calls.Add(1)
		}
		return nil
	}
}

func mustServerConfig(t *testing.T, fixture testFixture) *tls.Config {
	t.Helper()
	config, err := NewServerConfig(
		fixture.serverCertificate,
		fixture.clientAuthority.pool,
		testTrustDomain,
		trustDomainValidator(testTrustDomain, nil),
	)
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func rawServerConfig(certificate tls.Certificate, clientCAs *x509.CertPool) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs.Clone(),
	}
}

func forcedClientConfig(certificate tls.Certificate, roots *x509.CertPool) *tls.Config {
	return &tls.Config{
		RootCAs:            roots.Clone(),
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
		VerifyConnection: verifyServerSPIFFEConnection(
			roots.Clone(),
			testTrustDomain,
			trustDomainValidator(testTrustDomain, nil),
		),
		GetClientCertificate: fixedClientCertificate(certificate),
	}
}

func fixedClientCertificate(
	certificate tls.Certificate,
) func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return &certificate, nil
	}
}

func runHandshake(
	t *testing.T,
	serverConfig *tls.Config,
	clientConfig *tls.Config,
) handshakeResult {
	t.Helper()
	serverNetwork, clientNetwork := net.Pipe()
	deadline := time.Now().Add(5 * time.Second)
	if err := serverNetwork.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := clientNetwork.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- tls.Server(serverNetwork, serverConfig).Handshake()
	}()

	clientError := tls.Client(clientNetwork, clientConfig).Handshake()
	if err := clientNetwork.Close(); err != nil {
		t.Fatal(err)
	}
	serverError := <-serverErrors
	if err := serverNetwork.Close(); err != nil {
		t.Fatal(err)
	}
	return handshakeResult{client: clientError, server: serverError}
}

func cloneTLSCertificate(certificate tls.Certificate) tls.Certificate {
	cloned := certificate
	cloned.Certificate = cloneByteSlices(certificate.Certificate)
	cloned.OCSPStaple = append([]byte(nil), certificate.OCSPStaple...)
	cloned.SignedCertificateTimestamps = cloneByteSlices(certificate.SignedCertificateTimestamps)
	return cloned
}
