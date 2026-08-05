// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package trust

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestPublicDocumentAllowlistContainsExactlyEightPathFamilies(t *testing.T) {
	t.Parallel()

	identity, _ := testIdentity(t)
	ocspPath, err := OCSPPath(strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	crlPath, err := CRLPath(testNow)
	if err != nil {
		t.Fatal(err)
	}
	devicePath, err := DeviceIdentityPath(identity.PeerID)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		path      string
		mediaType string
		content   []byte
	}{
		{PathSPIFFEBundle, mediaTypeJSON, []byte(`{"keys":[]}`)},
		{
			PathOpenIDConfiguration,
			mediaTypeJSON,
			[]byte(`{"issuer":"https://example.invalid","token_endpoint":"https://example.invalid/token"}`),
		},
		{PathDeviceDocument, mediaTypeJSON, []byte(`{"device":"public"}`)},
		{PathFederationDocument, mediaTypeJSON, []byte(`{"federations":[]}`)},
		{ocspPath, mediaTypeOCSP, []byte{0x30, 0x00}},
		{crlPath, mediaTypeCRL, []byte{0x30, 0x00}},
		{PathUpdateManifest, mediaTypeJSON, []byte(`{"updates":[]}`)},
		{devicePath, mediaTypeJSON, []byte(`{"identity":"public"}`)},
	}
	for _, test := range tests {
		test := test
		t.Run(test.path, func(t *testing.T) {
			t.Parallel()
			document, err := NewPublicDocument(
				test.path,
				test.mediaType,
				test.content,
			)
			if err != nil {
				t.Fatal(err)
			}
			if document.Path() != test.path ||
				document.MediaType() != test.mediaType {
				t.Fatalf("document = %#v", document)
			}
		})
	}
}

func TestPublicDocumentRejectsPrivateAndUndeclaredData(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		path      string
		mediaType string
		content   []byte
	}{
		{
			name:      "private PEM",
			path:      PathDeviceDocument,
			mediaType: mediaTypeJSON,
			content: []byte(
				`{"public":"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"}`,
			),
		},
		{
			name:      "secret JSON field",
			path:      PathDeviceDocument,
			mediaType: mediaTypeJSON,
			content:   []byte(`{"cluster_secret":"canary"}`),
		},
		{
			name:      "undeclared path",
			path:      "/private/state.json",
			mediaType: mediaTypeJSON,
			content:   []byte(`{"public":true}`),
		},
		{
			name:      "traversal",
			path:      "/device/../identity",
			mediaType: mediaTypeJSON,
			content:   []byte(`{"public":true}`),
		},
		{
			name:      "wrong media type",
			path:      PathSPIFFEBundle,
			mediaType: "application/octet-stream",
			content:   []byte(`{"keys":[]}`),
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewPublicDocument(
				test.path,
				test.mediaType,
				test.content,
			); err == nil {
				t.Fatal("NewPublicDocument succeeded")
			}
		})
	}
}

func TestPublicationDigestCloneAndReceiptBinding(t *testing.T) {
	t.Parallel()

	identity, _ := testIdentity(t)
	document, err := NewPublicDocument(
		PathDeviceDocument,
		mediaTypeJSON,
		[]byte(`{"public":true}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := newPublication(
		identity,
		7,
		[]PublicDocument{document},
		testNow,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := publication.Validate(); err != nil {
		t.Fatal(err)
	}
	cloned := publication.Clone()
	cloned.Documents[0].content[0] ^= 0xff
	if err := publication.Validate(); err != nil {
		t.Fatalf("mutating clone changed original: %v", err)
	}
	if err := cloned.Validate(); err == nil {
		t.Fatal("tampered publication validated")
	}
	receipt := PublicationReceipt{
		PublicationID: publication.ID,
		Digest:        publication.Digest,
		IPNSName:      publication.IPNSName,
		RootCID:       identity.CanonicalIPNS,
		IPNSSequence:  9,
	}
	if err := validatePublicationReceipt(receipt, publication, 8); err != nil {
		t.Fatal(err)
	}
	receipt.Digest = strings.Repeat("0", 64)
	if err := validatePublicationReceipt(receipt, publication, 8); err == nil {
		t.Fatal("mismatched receipt validated")
	}
}

func TestPublicDocumentRejectsSymlinkStylePaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		path      string
		mediaType string
		content   []byte
	}{
		{
			name:      "null byte in path",
			path:      "/spiffe-bundle.json\x00",
			mediaType: mediaTypeJSON,
			content:   []byte(`{"keys":[]}`),
		},
		{
			name:      "backslash separator",
			path:      `/spiffe-bundle.json\extra`,
			mediaType: mediaTypeJSON,
			content:   []byte(`{"keys":[]}`),
		},
		{
			name:      "percent encoded slash",
			path:      "/spiffe-bundle%2F.json",
			mediaType: mediaTypeJSON,
			content:   []byte(`{"keys":[]}`),
		},
		{
			name:      "query string",
			path:      "/spiffe-bundle.json?v=1",
			mediaType: mediaTypeJSON,
			content:   []byte(`{"keys":[]}`),
		},
		{
			name:      "fragment",
			path:      "/spiffe-bundle.json#section",
			mediaType: mediaTypeJSON,
			content:   []byte(`{"keys":[]}`),
		},
		{
			name:      "double slash prefix",
			path:      "//spiffe-bundle.json",
			mediaType: mediaTypeJSON,
			content:   []byte(`{"keys":[]}`),
		},
		{
			name:      "double slash embedded",
			path:      "/spiffe//bundle.json",
			mediaType: mediaTypeJSON,
			content:   []byte(`{"keys":[]}`),
		},
		{
			name:      "empty path",
			path:      "",
			mediaType: mediaTypeJSON,
			content:   []byte(`{"keys":[]}`),
		},
		{
			name:      "relative path",
			path:      "spiffe-bundle.json",
			mediaType: mediaTypeJSON,
			content:   []byte(`{"keys":[]}`),
		},
		{
			name:      "tab in path",
			path:      "/spiffe-bundle\t.json",
			mediaType: mediaTypeJSON,
			content:   []byte(`{"keys":[]}`),
		},
		{
			name:      "newline in path",
			path:      "/spiffe-bundle\n.json",
			mediaType: mediaTypeJSON,
			content:   []byte(`{"keys":[]}`),
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewPublicDocument(
				test.path,
				test.mediaType,
				test.content,
			); err == nil {
				t.Fatalf(
					"NewPublicDocument accepted invalid path %q",
					test.path,
				)
			}
		})
	}
}

func TestPublicDocumentRejectsPathTraversal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		path      string
		mediaType string
		content   []byte
	}{
		{
			name:      "parent traversal",
			path:      "/device/../identity",
			mediaType: mediaTypeJSON,
			content:   []byte(`{"public":true}`),
		},
		{
			name:      "double parent traversal",
			path:      "/a/../b/../c",
			mediaType: mediaTypeJSON,
			content:   []byte(`{"public":true}`),
		},
		{
			name:      "traversal from root",
			path:      "/../etc/passwd",
			mediaType: mediaTypeJSON,
			content:   []byte(`{"public":true}`),
		},
		{
			name:      "traversal to allowed path",
			path:      "/etc/../../../spiffe-bundle.json",
			mediaType: mediaTypeJSON,
			content:   []byte(`{"keys":[]}`),
		},
		{
			name:      "OCSP traversal",
			path:      "/ocsp/../../spiffe-bundle.json",
			mediaType: mediaTypeJSON,
			content:   []byte(`{"keys":[]}`),
		},
		{
			name:      "CRL traversal",
			path:      "/crl/../../device/secret",
			mediaType: mediaTypeJSON,
			content:   []byte(`{"public":true}`),
		},
		{
			name:      "device traversal",
			path:      "/device/../../private/key",
			mediaType: mediaTypeJSON,
			content:   []byte(`{"public":true}`),
		},
		{
			name:      "well-known traversal",
			path:      "/.well-known/../private",
			mediaType: mediaTypeJSON,
			content:   []byte(`{"public":true}`),
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewPublicDocument(
				test.path,
				test.mediaType,
				test.content,
			); err == nil {
				t.Fatalf(
					"NewPublicDocument accepted traversal path %q",
					test.path,
				)
			}
		})
	}
}

func TestPublicDocumentRejectsAllPrivatePEMVariants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		path      string
		mediaType string
		content   []byte
	}{
		{
			name:      "PKCS8 private key",
			path:      PathDeviceDocument,
			mediaType: mediaTypeJSON,
			content: []byte(
				`{"data":"-----BEGIN PRIVATE KEY-----\nMIIB...\n-----END PRIVATE KEY-----"}`,
			),
		},
		{
			name:      "encrypted private key",
			path:      PathDeviceDocument,
			mediaType: mediaTypeJSON,
			content: []byte(
				`{"data":"-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIF...\n-----END ENCRYPTED PRIVATE KEY-----"}`,
			),
		},
		{
			name:      "RSA private key",
			path:      PathDeviceDocument,
			mediaType: mediaTypeJSON,
			content: []byte(
				`{"data":"-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"}`,
			),
		},
		{
			name:      "EC private key",
			path:      PathDeviceDocument,
			mediaType: mediaTypeJSON,
			content: []byte(
				`{"data":"-----BEGIN EC PRIVATE KEY-----\nMHQ...\n-----END EC PRIVATE KEY-----"}`,
			),
		},
		{
			name:      "OpenSSH private key",
			path:      PathDeviceDocument,
			mediaType: mediaTypeJSON,
			content: []byte(
				`{"data":"-----BEGIN OPENSSH PRIVATE KEY-----\nb3Bl...\n-----END OPENSSH PRIVATE KEY-----"}`,
			),
		},
		{
			name:      "private key uppercase marker",
			path:      PathDeviceDocument,
			mediaType: mediaTypeJSON,
			content: []byte(
				`{"data":"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"}`,
			),
		},
		{
			name:      "private key mixed case marker",
			path:      PathDeviceDocument,
			mediaType: mediaTypeJSON,
			content: []byte(
				`{"data":"-----BEGIN Private Key-----\nAAAA\n-----END Private Key-----"}`,
			),
		},
		{
			name:      "private key in OCSP path",
			path:      "/ocsp/" + strings.Repeat("a", 64),
			mediaType: mediaTypeOCSP,
			content: []byte(
				"-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----",
			),
		},
		{
			name:      "private key in CRL path",
			path:      "/crl/" + testNow.Format("20060102T150405Z"),
			mediaType: mediaTypeCRL,
			content: []byte(
				"-----BEGIN EC PRIVATE KEY-----\nMHQ...\n-----END EC PRIVATE KEY-----",
			),
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewPublicDocument(
				test.path,
				test.mediaType,
				test.content,
			); err == nil {
				t.Fatal(
					"NewPublicDocument accepted content with private PEM",
				)
			}
		})
	}
}

func TestPublicDocumentRejectsAllForbiddenJSONKeys(t *testing.T) {
	t.Parallel()

	forbidden := []string{
		"clustersecret",
		"credential",
		"password",
		"passphrase",
		"privatekey",
		"secret",
		"signingkey",
		"token",
	}
	for _, key := range forbidden {
		key := key
		t.Run(key, func(t *testing.T) {
			t.Parallel()
			content := fmt.Sprintf(`{"%s":"canary"}`, key)
			if _, err := NewPublicDocument(
				PathDeviceDocument,
				mediaTypeJSON,
				[]byte(content),
			); err == nil {
				t.Fatalf(
					"NewPublicDocument accepted forbidden JSON key %q",
					key,
				)
			}
		})
	}

	separatorVariants := []struct {
		name string
		key  string
	}{
		{"underscore", "cluster_secret"},
		{"hyphen", "cluster-secret"},
		{"dot", "cluster.secret"},
		{"mixed underscore", "cluster_Secret"},
		{"mixed hyphen", "cluster-Secret"},
		{"mixed dot", "cluster.Secret"},
		{"nested secret", `{"outer":{"secret":"canary"}}`},
		{"array secret", `{"items":[{"token":"canary"}]}`},
	}
	for _, variant := range separatorVariants {
		variant := variant
		t.Run(variant.name, func(t *testing.T) {
			t.Parallel()
			var content string
			if variant.key[0] == '{' {
				content = variant.key
			} else {
				content = fmt.Sprintf(
					`{"%s":"canary"}`,
					variant.key,
				)
			}
			if _, err := NewPublicDocument(
				PathDeviceDocument,
				mediaTypeJSON,
				[]byte(content),
			); err == nil {
				t.Fatalf(
					"NewPublicDocument accepted forbidden JSON key variant %q",
					variant.key,
				)
			}
		})
	}
}

func TestPublicDocumentRejectsJSONPrivateKeyInValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		path      string
		mediaType string
		content   []byte
	}{
		{
			name:      "RSA private key in value",
			path:      PathSPIFFEBundle,
			mediaType: mediaTypeJSON,
			content: []byte(
				`{"keys":["-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----"]}`,
			),
		},
		{
			name:      "EC private key in nested value",
			path:      PathFederationDocument,
			mediaType: mediaTypeJSON,
			content: []byte(
				`{"federations":[{"key":"-----BEGIN EC PRIVATE KEY-----\nMHQ\n-----END EC PRIVATE KEY-----"}]}`,
			),
		},
		{
			name:      "OpenSSH key in array element",
			path:      PathUpdateManifest,
			mediaType: mediaTypeJSON,
			content: []byte(
				`{"updates":["-----BEGIN OPENSSH PRIVATE KEY-----\nb3Bl\n-----END OPENSSH PRIVATE KEY-----"]}`,
			),
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewPublicDocument(
				test.path,
				test.mediaType,
				test.content,
			); err == nil {
				t.Fatalf(
					"NewPublicDocument accepted private key in JSON value for %q",
					test.path,
				)
			}
		})
	}
}

func TestPublicDocumentRejectsDeeplyNestedJSON(t *testing.T) {
	t.Parallel()

	content := `{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":{"j":{"k":{"l":{"m":{"n":{"o":{"p":{"q":{"r":{"s":{"t":{"u":{"v":{"w":{"x":{"y":{"z":{"aa":{"bb":{"cc":{"dd":{"ee":{"ff":{"gg":1}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}`
	if _, err := NewPublicDocument(
		PathDeviceDocument,
		mediaTypeJSON,
		[]byte(content),
	); err == nil {
		t.Fatal("NewPublicDocument accepted deeply nested JSON")
	}
}

func TestPublicDocumentRejectsMultipleJSONValues(t *testing.T) {
	t.Parallel()

	if _, err := NewPublicDocument(
		PathDeviceDocument,
		mediaTypeJSON,
		[]byte(`{"a":1}{"b":2}`),
	); err == nil {
		t.Fatal("NewPublicDocument accepted multiple JSON values")
	}
}

func TestPublicDocumentRejectsNonObjectJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
	}{
		{"array", `["not","an","object"]`},
		{"string", `"just a string"`},
		{"number", `42`},
		{"boolean", `true`},
		{"null", `null`},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewPublicDocument(
				PathDeviceDocument,
				mediaTypeJSON,
				[]byte(test.content),
			); err == nil {
				t.Fatal("NewPublicDocument accepted non-object JSON")
			}
		})
	}
}

func TestPublicDocumentRejectsEmptyContent(t *testing.T) {
	t.Parallel()

	if _, err := NewPublicDocument(
		PathDeviceDocument,
		mediaTypeJSON,
		[]byte{},
	); err == nil {
		t.Fatal("NewPublicDocument accepted empty content")
	}
	if _, err := NewPublicDocument(
		PathDeviceDocument,
		mediaTypeJSON,
		nil,
	); err == nil {
		t.Fatal("NewPublicDocument accepted nil content")
	}
}

func TestPublicDocumentRejectsOversizedContent(t *testing.T) {
	t.Parallel()

	oversized := make([]byte, maximumPublicDocumentBytes+1)
	for i := range oversized {
		oversized[i] = 'x'
	}
	if _, err := NewPublicDocument(
		PathDeviceDocument,
		mediaTypeJSON,
		oversized,
	); err == nil {
		t.Fatal("NewPublicDocument accepted oversized content")
	}
}

func TestOCSPPathRejectsInvalidStatusIDs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status string
	}{
		{"too short", strings.Repeat("a", 63)},
		{"too long", strings.Repeat("a", 65)},
		{"uppercase", strings.Repeat("A", 64)},
		{"non-hex", strings.Repeat("g", 64)},
		{"empty", ""},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := OCSPPath(test.status); err == nil {
				t.Fatalf(
					"OCSPPath accepted invalid status ID %q",
					test.status,
				)
			}
		})
	}
}

func TestCRLPathRejectsInvalidTimestamps(t *testing.T) {
	t.Parallel()

	_, err := CRLPath(time.Time{})
	if err == nil {
		t.Fatal("CRLPath accepted zero time")
	}

	_, err = CRLPath(time.Date(2026, 7, 28, 12, 0, 0, 1, time.UTC))
	if err == nil {
		t.Fatal("CRLPath accepted non-whole-second time")
	}

	localTime := time.Date(2026, 7, 28, 12, 0, 0, 0, time.Local)
	_, err = CRLPath(localTime)
	if err == nil {
		t.Fatal("CRLPath accepted non-UTC time")
	}
}

func TestDeviceIdentityPathRejectsInvalidPeerIDs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		peerID string
	}{
		{"empty", ""},
		{"garbage", "not-a-peer-id"},
		{"with prefix", "/ipns/12D3KooWTest"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := DeviceIdentityPath(test.peerID); err == nil {
				t.Fatalf(
					"DeviceIdentityPath accepted invalid peer ID %q",
					test.peerID,
				)
			}
		})
	}
}

func TestPublicationBuildsDocumentForEachPathType(t *testing.T) {
	t.Parallel()

	identity, _ := testIdentity(t)
	ocspPath, err := OCSPPath(strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	crlPath, err := CRLPath(testNow)
	if err != nil {
		t.Fatal(err)
	}
	devicePath, err := DeviceIdentityPath(identity.PeerID)
	if err != nil {
		t.Fatal(err)
	}

	pathTypes := []struct {
		path      string
		mediaType string
		content   []byte
	}{
		{PathSPIFFEBundle, mediaTypeJSON, []byte(`{"keys":[]}`)},
		{PathOpenIDConfiguration, mediaTypeJSON, []byte(`{"issuer":"https://example.invalid","token_endpoint":"https://example.invalid/token"}`)},
		{PathDeviceDocument, mediaTypeJSON, []byte(`{"device":"public"}`)},
		{PathFederationDocument, mediaTypeJSON, []byte(`{"federations":[]}`)},
		{ocspPath, mediaTypeOCSP, []byte{0x30, 0x00}},
		{crlPath, mediaTypeCRL, []byte{0x30, 0x00}},
		{PathUpdateManifest, mediaTypeJSON, []byte(`{"updates":[]}`)},
		{devicePath, mediaTypeJSON, []byte(`{"identity":"public"}`)},
	}
	for _, entry := range pathTypes {
		entry := entry
		t.Run(entry.path, func(t *testing.T) {
			t.Parallel()
			document, err := NewPublicDocument(
				entry.path,
				entry.mediaType,
				entry.content,
			)
			if err != nil {
				t.Fatal(err)
			}
			publication, err := newPublication(
				identity,
				1,
				[]PublicDocument{document},
				testNow,
			)
			if err != nil {
				t.Fatal(err)
			}
			if err := publication.Validate(); err != nil {
				t.Fatal(err)
			}
			if len(publication.Documents) != 1 {
				t.Fatalf(
					"publication has %d documents, want 1",
					len(publication.Documents),
				)
			}
			if publication.Documents[0].Path() != entry.path {
				t.Fatalf(
					"document path = %q, want %q",
					publication.Documents[0].Path(),
					entry.path,
				)
			}
			if publication.Documents[0].MediaType() != entry.mediaType {
				t.Fatalf(
					"document media type = %q, want %q",
					publication.Documents[0].MediaType(),
					entry.mediaType,
				)
			}
			if string(publication.Documents[0].Content()) != string(entry.content) {
				t.Fatal("document content does not match")
			}
		})
	}
}

func TestContentScrubbingRejectsSecretsInAllDocumentTypes(t *testing.T) {
	t.Parallel()

	identity, _ := testIdentity(t)
	devicePath, err := DeviceIdentityPath(identity.PeerID)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		path      string
		mediaType string
		content   []byte
	}{
		{
			name:      "SPIFFE bundle with secret field",
			path:      PathSPIFFEBundle,
			mediaType: mediaTypeJSON,
			content:   []byte(`{"keys":[],"secret":"canary"}`),
		},
		{
			name:      "OIDC config with password",
			path:      PathOpenIDConfiguration,
			mediaType: mediaTypeJSON,
			content:   []byte(`{"issuer":"x","password":"canary"}`),
		},
		{
			name:      "device doc with credential",
			path:      PathDeviceDocument,
			mediaType: mediaTypeJSON,
			content:   []byte(`{"device":"x","credential":"canary"}`),
		},
		{
			name:      "federation doc with signing_key",
			path:      PathFederationDocument,
			mediaType: mediaTypeJSON,
			content:   []byte(`{"federations":[],"signing_key":"canary"}`),
		},
		{
			name:      "update manifest with privatekey",
			path:      PathUpdateManifest,
			mediaType: mediaTypeJSON,
			content:   []byte(`{"updates":[],"privatekey":"canary"}`),
		},
		{
			name:      "device identity with token",
			path:      devicePath,
			mediaType: mediaTypeJSON,
			content:   []byte(`{"identity":"public","token":"canary"}`),
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewPublicDocument(
				test.path,
				test.mediaType,
				test.content,
			); err == nil {
				t.Fatalf(
					"NewPublicDocument accepted forbidden key in %q",
					test.path,
				)
			}
		})
	}
}

func TestPublicationRejectsPublicationWithSecrets(t *testing.T) {
	t.Parallel()

	identity, _ := testIdentity(t)

	secretDoc, err := NewPublicDocument(
		PathDeviceDocument,
		mediaTypeJSON,
		[]byte(`{"device":"ok"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := newPublication(
		identity,
		1,
		[]PublicDocument{secretDoc},
		testNow,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Mutate the document to include a forbidden key after construction.
	publication.Documents[0].content = []byte(
		`{"device":"ok","password":"canary"}`,
	)
	if err := publication.Validate(); err == nil {
		t.Fatal("publication with forbidden key in mutated document validated")
	}
}

func TestPublicationRejectsDuplicatePaths(t *testing.T) {
	t.Parallel()

	identity, _ := testIdentity(t)
	doc1, err := NewPublicDocument(
		PathDeviceDocument,
		mediaTypeJSON,
		[]byte(`{"device":"first"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	doc2, err := NewPublicDocument(
		PathDeviceDocument,
		mediaTypeJSON,
		[]byte(`{"device":"second"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = newPublication(
		identity,
		1,
		[]PublicDocument{doc1, doc2},
		testNow,
	)
	if err == nil {
		t.Fatal("newPublication accepted duplicate paths")
	}
}
