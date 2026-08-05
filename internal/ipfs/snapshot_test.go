// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package ipfs

import (
	"strings"
	"testing"

	"github.com/sovereignite/sovereignite/internal/trust"
)

func TestPublicSnapshotAcceptsExactlyEightPathFamilies(t *testing.T) {
	t.Parallel()
	signer := newTestSigner(t)
	publication := testPublication(t, signer, 1, "first")
	snapshot, err := NewPublicSnapshot(publication, signer.Name())
	if err != nil {
		t.Fatalf("validate complete public snapshot: %v", err)
	}
	files := snapshot.Files()
	if len(files) != 8 {
		t.Fatalf("file count = %d, want 8", len(files))
	}
	for _, file := range files {
		if _, err := validateAllowedPath(file.Path); err != nil {
			t.Fatalf("allowlisted path %q was rejected: %v", file.Path, err)
		}
	}
}

func TestAllowlistRejectsTraversalExtensionsAndUndeclaredPaths(
	t *testing.T,
) {
	t.Parallel()
	for _, path := range []string{
		"",
		"/spiffe-bundle.json/extra",
		"/spiffe-bundle.json.bak",
		"/.well-known/sovereignite/ct",
		"/ocsp/abc",
		"/ocsp/" + strings.Repeat("A", 64),
		"/ocsp/" + strings.Repeat("a", 64) + ".der",
		"/crl/20260728T120000Z.pem",
		"/crl/20261399T999999Z",
		"/device/not-a-peer/identity",
		"/device/../identity",
		"/updates/../secret",
		"/updates/%2e%2e/secret",
		"/private-key",
		"/cluster-secret",
	} {
		if _, err := validateAllowedPath(path); err == nil {
			t.Fatalf("undeclared path %q was accepted", path)
		}
	}
}

func TestPublicSnapshotRejectsWrongIdentityAndDigest(t *testing.T) {
	t.Parallel()
	signer := newTestSigner(t)
	other := newTestSigner(t)
	publication := testPublication(t, signer, 1, "first")
	if _, err := NewPublicSnapshot(publication, other.Name()); err == nil {
		t.Fatal("publication bound to another IPNS name was accepted")
	}
	publication.Digest = strings.Repeat("0", 64)
	if _, err := NewPublicSnapshot(publication, signer.Name()); err == nil {
		t.Fatal("publication with changed digest was accepted")
	}
}

func TestPublicDocumentBoundaryRejectsPrivateMaterial(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		content []byte
	}{
		{
			name: "private PEM",
			content: []byte(
				`{"value":"-----BEGIN PRIVATE KEY-----\ncanary"}`,
			),
		},
		{
			name:    "private JSON field",
			content: []byte(`{"private_key":"private-canary"}`),
		},
		{
			name:    "cluster secret field",
			content: []byte(`{"cluster_secret":"cluster-canary"}`),
		},
		{
			name:    "user data field",
			content: []byte(`{"credential":"user-canary"}`),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := trust.NewPublicDocument(
				pathDeviceDocument,
				mediaTypeJSON,
				test.content,
			)
			if err == nil {
				t.Fatal("private material was accepted as public")
			}
		})
	}
}

func TestPublicSnapshotCopiesCallerBytes(t *testing.T) {
	t.Parallel()
	signer := newTestSigner(t)
	publication := testPublication(t, signer, 1, "copy")
	snapshot, err := NewPublicSnapshot(publication, signer.Name())
	if err != nil {
		t.Fatalf("create snapshot: %v", err)
	}
	files := snapshot.Files()
	files[0].Content[0] ^= 0xff
	again := snapshot.Files()
	if len(again[0].Content) == 0 || again[0].Content[0] == files[0].Content[0] {
		t.Fatal("snapshot content was mutable through returned bytes")
	}
}

func TestTrustPublicationValidationRemainsMandatory(t *testing.T) {
	t.Parallel()
	signer := newTestSigner(t)
	publication := testPublication(t, signer, 1, "valid")
	publication.ID = strings.Repeat("f", 64)
	_, err := NewPublicSnapshot(publication, signer.Name())
	if err == nil {
		t.Fatal("invalid Trust publication was accepted")
	}
	if !strings.Contains(err.Error(), "digest") {
		t.Fatalf("unexpected validation error: %v", err)
	}
}
