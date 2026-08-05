// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package trust

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/ipfs/go-cid"
	"github.com/libp2p/go-libp2p/core/peer"
)

const (
	// PathSPIFFEBundle is the exact public SPIFFE bundle path named by v5.
	PathSPIFFEBundle = "/spiffe-bundle.json"
	// PathOpenIDConfiguration is the exact public OIDC discovery mirror path.
	PathOpenIDConfiguration = "/.well-known/openid-configuration"
	// PathDeviceDocument is the exact public device metadata path.
	PathDeviceDocument = "/.well-known/sovereignite/device"
	// PathFederationDocument is the exact public federation metadata path.
	PathFederationDocument = "/.well-known/sovereignite/federation"
	// PathUpdateManifest is the exact public update manifest path.
	PathUpdateManifest = "/updates/manifest.json"

	mediaTypeJSON = "application/json"
	mediaTypeOCSP = "application/ocsp-response"
	mediaTypeCRL  = "application/pkix-crl"

	maximumPublicDocumentBytes = 1 << 20
	maximumPublicationBytes    = 4 << 20
	maximumPublicationDocs     = 256
	maximumJSONDepth           = 32

	publicationDigestDomain = "github.com/sovereignite/sovereignite/trust-publication/v1\x00"
)

var (
	certificateIDPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
	compactTimePattern   = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z$`)
	privatePEMMarkers    = [][]byte{
		[]byte("-----BEGIN PRIVATE KEY-----"),
		[]byte("-----BEGIN ENCRYPTED PRIVATE KEY-----"),
		[]byte("-----BEGIN RSA PRIVATE KEY-----"),
		[]byte("-----BEGIN EC PRIVATE KEY-----"),
		[]byte("-----BEGIN OPENSSH PRIVATE KEY-----"),
	}
	forbiddenPublicJSONKeys = map[string]struct{}{
		"clustersecret": {},
		"credential":    {},
		"password":      {},
		"passphrase":    {},
		"privatekey":    {},
		"secret":        {},
		"signingkey":    {},
		"token":         {},
	}
)

// PublicDocument is an immutable public-only document whose path belongs to
// the mechanically closed v5 allowlist.
type PublicDocument struct {
	path      string
	mediaType string
	content   []byte
}

// NewPublicDocument validates one complete public document. Dynamic path
// components must already be in their canonical forms produced by OCSPPath,
// CRLPath, or DeviceIdentityPath.
func NewPublicDocument(
	path string,
	mediaType string,
	content []byte,
) (PublicDocument, error) {
	expectedMediaType, err := validatePublicPath(path)
	if err != nil {
		return PublicDocument{}, err
	}
	if mediaType != expectedMediaType {
		return PublicDocument{}, fmt.Errorf(
			"public document %q media type is %q, want %q",
			path,
			mediaType,
			expectedMediaType,
		)
	}
	if len(content) == 0 || len(content) > maximumPublicDocumentBytes {
		return PublicDocument{}, fmt.Errorf(
			"public document %q must be nonempty and at most %d bytes",
			path,
			maximumPublicDocumentBytes,
		)
	}
	if containsPrivatePEM(content) {
		return PublicDocument{}, errors.New(
			"public document contains private-key PEM material",
		)
	}
	if mediaType == mediaTypeJSON {
		if err := validatePublicJSON(content); err != nil {
			return PublicDocument{}, fmt.Errorf(
				"public document %q: %w",
				path,
				err,
			)
		}
	}
	return PublicDocument{
		path:      path,
		mediaType: mediaType,
		content:   slices.Clone(content),
	}, nil
}

// Path returns the canonical public path.
func (d PublicDocument) Path() string {
	return d.path
}

// MediaType returns the exact media type required for this path family.
func (d PublicDocument) MediaType() string {
	return d.mediaType
}

// Content returns a copy of the public bytes.
func (d PublicDocument) Content() []byte {
	return slices.Clone(d.content)
}

// MarshalJSON persists only the validated public representation.
func (d PublicDocument) MarshalJSON() ([]byte, error) {
	if _, err := NewPublicDocument(d.path, d.mediaType, d.content); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Path      string `json:"path"`
		MediaType string `json:"media_type"`
		Content   []byte `json:"content"`
	}{
		Path:      d.path,
		MediaType: d.mediaType,
		Content:   d.content,
	})
}

// UnmarshalJSON validates durable public bytes before accepting them.
func (d *PublicDocument) UnmarshalJSON(encoded []byte) error {
	if d == nil {
		return errors.New("public document receiver is nil")
	}
	var wire struct {
		Path      string `json:"path"`
		MediaType string `json:"media_type"`
		Content   []byte `json:"content"`
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("public document contains multiple JSON values")
		}
		return err
	}
	document, err := NewPublicDocument(wire.Path, wire.MediaType, wire.Content)
	if err != nil {
		return err
	}
	*d = document
	return nil
}

// OCSPPath constructs the sole public OCSP path form. Status IDs are lowercase
// SHA-256 values: issued-certificate fingerprints or deterministic locators
// for serials whose post-sign outcome is uncertain.
func OCSPPath(statusID string) (string, error) {
	if !certificateIDPattern.MatchString(statusID) {
		return "", errors.New("OCSP status ID must be a lowercase SHA-256 value")
	}
	return "/ocsp/" + statusID, nil
}

// CRLPath constructs the sole public CRL path form using a canonical UTC
// second. The protocol authority and retention policy remain behind D-011.
func CRLPath(timestamp time.Time) (string, error) {
	if timestamp.IsZero() || timestamp.Location() != time.UTC ||
		timestamp.Nanosecond() != 0 {
		return "", errors.New("CRL timestamp must be a whole UTC second")
	}
	return "/crl/" + timestamp.Format("20060102T150405Z"), nil
}

// DeviceIdentityPath constructs the sole per-device identity path.
func DeviceIdentityPath(canonicalPeerID string) (string, error) {
	peerID, err := peer.Decode(canonicalPeerID)
	if err != nil {
		return "", fmt.Errorf("decode identity path peer ID: %w", err)
	}
	if peerID.String() != canonicalPeerID {
		return "", errors.New("identity path peer ID is not canonical")
	}
	return "/device/" + canonicalPeerID + "/identity", nil
}

func validatePublicPath(path string) (string, error) {
	if path == "" ||
		strings.Contains(path, "\\") ||
		strings.Contains(path, "%") ||
		strings.ContainsRune(path, '\x00') ||
		strings.Contains(path, "?") ||
		strings.Contains(path, "#") ||
		strings.Contains(path, "//") {
		return "", errors.New("public document path has an invalid form")
	}
	switch path {
	case PathSPIFFEBundle,
		PathOpenIDConfiguration,
		PathDeviceDocument,
		PathFederationDocument,
		PathUpdateManifest:
		return mediaTypeJSON, nil
	}
	if strings.HasPrefix(path, "/ocsp/") {
		component := strings.TrimPrefix(path, "/ocsp/")
		canonical, err := OCSPPath(component)
		if err != nil || canonical != path {
			return "", errors.New("public OCSP path is invalid")
		}
		return mediaTypeOCSP, nil
	}
	if strings.HasPrefix(path, "/crl/") {
		component := strings.TrimPrefix(path, "/crl/")
		if !compactTimePattern.MatchString(component) {
			return "", errors.New("public CRL path timestamp is invalid")
		}
		timestamp, err := time.Parse("20060102T150405Z", component)
		if err != nil {
			return "", errors.New("public CRL path timestamp is invalid")
		}
		canonical, err := CRLPath(timestamp.UTC())
		if err != nil || canonical != path {
			return "", errors.New("public CRL path is not canonical")
		}
		return mediaTypeCRL, nil
	}
	if strings.HasPrefix(path, "/device/") &&
		strings.HasSuffix(path, "/identity") {
		component := strings.TrimSuffix(
			strings.TrimPrefix(path, "/device/"),
			"/identity",
		)
		canonical, err := DeviceIdentityPath(component)
		if err != nil || canonical != path {
			return "", errors.New("public device identity path is invalid")
		}
		return mediaTypeJSON, nil
	}
	return "", errors.New("public document path is outside the v5 allowlist")
}

func containsPrivatePEM(content []byte) bool {
	upper := bytes.ToUpper(content)
	for _, marker := range privatePEMMarkers {
		if bytes.Contains(upper, marker) {
			return true
		}
	}
	return false
}

func validatePublicJSON(content []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return fmt.Errorf("decode JSON: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON contains multiple values")
		}
		return fmt.Errorf("decode trailing JSON: %w", err)
	}
	if _, ok := value.(map[string]any); !ok {
		return errors.New("JSON public document must be an object")
	}
	return inspectPublicJSON(value, 0)
}

func inspectPublicJSON(value any, depth int) error {
	if depth > maximumJSONDepth {
		return errors.New("JSON public document nesting is too deep")
	}
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			normalized := strings.NewReplacer(
				"_", "",
				"-", "",
				".", "",
			).Replace(strings.ToLower(key))
			if _, forbidden := forbiddenPublicJSONKeys[normalized]; forbidden {
				return fmt.Errorf("JSON field %q is not public data", key)
			}
			if err := inspectPublicJSON(child, depth+1); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range typed {
			if err := inspectPublicJSON(child, depth+1); err != nil {
				return err
			}
		}
	case string:
		if containsPrivatePEM([]byte(typed)) {
			return errors.New("JSON value contains private-key PEM material")
		}
	}
	return nil
}

// PublicStateView contains only state classified as public. Builders must not
// receive ownership principals, authorization grants, cluster state, or any
// private key material.
type PublicStateView struct {
	Revision                   uint64
	LocalIdentity              DeviceIdentity
	ActiveCACertificateDER     []byte
	Certificates               []PublicCertificate
	Revocations                []PublicRevocation
	Federations                []PublicFederation
}

// PublicCertificate is the public certificate subset available to a builder.
type PublicCertificate struct {
	ID          string
	SPIFFEID    string
	Serial      string
	DER         []byte
	NotBefore   time.Time
	NotAfter    time.Time
	Status      CertificateStatus
}

// PublicRevocation is the public revocation subset available to a builder.
type PublicRevocation struct {
	StatusID       string
	CertificateID  string
	Serial         string
	Kind           RevocationKind
	CertificateDER []byte
	RevokedAt      time.Time
}

// PublicFederation is one explicit directed, domain-keyed public edge.
type PublicFederation struct {
	SourceDomain           string
	TargetDomain           string
	SourceGeneration       uint64
	RemoteCACertificateDER []byte
	CrossCertificateDER    []byte
	EstablishedAt          time.Time
}

// PublicSnapshotBuilder renders authority-approved protocol bytes. D-011 keeps
// production builders disabled until each protocol document's semantics are
// fixed. Every returned document is independently revalidated by Service.
type PublicSnapshotBuilder interface {
	Build(context.Context, PublicStateView) ([]PublicDocument, error)
}

// Publisher atomically imports and publishes one immutable public snapshot.
// Repeated calls with the same Publication ID and digest must be idempotent.
type Publisher interface {
	Publish(context.Context, Publication) (PublicationReceipt, error)
}

// Publication is one immutable, digest-bound public-only outbox item.
type Publication struct {
	ID            string           `json:"id"`
	StateRevision uint64           `json:"state_revision"`
	IPNSName      string           `json:"ipns_name"`
	Digest        string           `json:"digest"`
	Documents     []PublicDocument `json:"documents"`
	CreatedAt     time.Time        `json:"created_at"`
}

// Validate independently proves the closed path allowlist, public-only
// document constraints, canonical IPNS name, deterministic ordering, ID, and
// digest. Publisher adapters should call it before importing any bytes.
func (p Publication) Validate() error {
	if p.StateRevision == 0 || p.CreatedAt.IsZero() {
		return errors.New("publication revision and creation time are required")
	}
	if _, err := TrustDomainFromIPNS(p.IPNSName); err != nil {
		return fmt.Errorf("publication IPNS name: %w", err)
	}
	documents := clonePublicDocuments(p.Documents)
	sort.Slice(documents, func(left, right int) bool {
		return documents[left].path < documents[right].path
	})
	if len(documents) == 0 || len(documents) > maximumPublicationDocs {
		return errors.New("publication has an invalid document count")
	}
	total := 0
	for index, document := range documents {
		if _, err := NewPublicDocument(
			document.path,
			document.mediaType,
			document.content,
		); err != nil {
			return err
		}
		total += len(document.content)
		if total > maximumPublicationBytes {
			return errors.New("publication public data exceeds 4 MiB")
		}
		if index > 0 && documents[index-1].path == document.path {
			return fmt.Errorf("publication contains duplicate path %q", document.path)
		}
	}
	digest := publicationDigest(p.IPNSName, p.StateRevision, documents)
	if p.ID != digest || p.Digest != digest {
		return errors.New("publication ID or digest does not match its documents")
	}
	return nil
}

// Clone returns a deep copy safe for an injected publisher to retain.
func (p Publication) Clone() Publication {
	cloned := p
	cloned.Documents = clonePublicDocuments(p.Documents)
	return cloned
}

// PublicationReceipt proves what the publisher advanced. The service accepts
// it only when its identity, content digest, IPNS name, CID, and sequence match
// the pending item and current monotonic publication state.
type PublicationReceipt struct {
	PublicationID string
	Digest        string
	IPNSName      string
	RootCID       string
	IPNSSequence  uint64
}

func newPublication(
	identity DeviceIdentity,
	revision uint64,
	documents []PublicDocument,
	now time.Time,
) (Publication, error) {
	if revision == 0 {
		return Publication{}, errors.New("publication revision must be positive")
	}
	if now.IsZero() {
		return Publication{}, errors.New("publication time is required")
	}
	if len(documents) == 0 || len(documents) > maximumPublicationDocs {
		return Publication{}, errors.New("publication has an invalid document count")
	}
	documents = clonePublicDocuments(documents)
	sort.Slice(documents, func(left, right int) bool {
		return documents[left].path < documents[right].path
	})
	total := 0
	for index, document := range documents {
		validated, err := NewPublicDocument(
			document.path,
			document.mediaType,
			document.content,
		)
		if err != nil {
			return Publication{}, err
		}
		documents[index] = validated
		total += len(validated.content)
		if total > maximumPublicationBytes {
			return Publication{}, errors.New("publication public data exceeds 4 MiB")
		}
		if index > 0 && documents[index-1].path == validated.path {
			return Publication{}, fmt.Errorf(
				"publication contains duplicate path %q",
				validated.path,
			)
		}
	}
	digest := publicationDigest(identity.CanonicalIPNS, revision, documents)
	return Publication{
		ID:            digest,
		StateRevision: revision,
		IPNSName:      identity.CanonicalIPNS,
		Digest:        digest,
		Documents:     documents,
		CreatedAt:     now.UTC(),
	}, nil
}

func validatePublication(publication Publication, identity DeviceIdentity) error {
	rebuilt, err := newPublication(
		identity,
		publication.StateRevision,
		publication.Documents,
		publication.CreatedAt,
	)
	if err != nil {
		return err
	}
	if publication.ID != rebuilt.ID ||
		publication.Digest != rebuilt.Digest ||
		publication.IPNSName != rebuilt.IPNSName {
		return errors.New("publication identity or digest does not match its documents")
	}
	return nil
}

func publicationDigest(
	ipnsName string,
	revision uint64,
	documents []PublicDocument,
) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte(publicationDigestDomain))
	writeDigestField(digest, []byte(ipnsName))
	var revisionBytes [8]byte
	binary.BigEndian.PutUint64(revisionBytes[:], revision)
	_, _ = digest.Write(revisionBytes[:])
	for _, document := range documents {
		writeDigestField(digest, []byte(document.path))
		writeDigestField(digest, []byte(document.mediaType))
		writeDigestField(digest, document.content)
	}
	return hex.EncodeToString(digest.Sum(nil))
}

type digestWriter interface {
	Write([]byte) (int, error)
}

func writeDigestField(writer digestWriter, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = writer.Write(value)
}

func validatePublicationReceipt(
	receipt PublicationReceipt,
	publication Publication,
	lastSequence uint64,
) error {
	if receipt.PublicationID != publication.ID ||
		receipt.Digest != publication.Digest ||
		receipt.IPNSName != publication.IPNSName {
		return errors.New("publication receipt is bound to different content")
	}
	rootCID, err := cid.Decode(receipt.RootCID)
	if err != nil || !rootCID.Defined() {
		return errors.New("publication receipt root CID is invalid")
	}
	if receipt.IPNSSequence <= lastSequence {
		return errors.New("publication receipt IPNS sequence is not monotonic")
	}
	return nil
}

func clonePublicDocuments(documents []PublicDocument) []PublicDocument {
	if documents == nil {
		return nil
	}
	cloned := make([]PublicDocument, len(documents))
	for index, document := range documents {
		cloned[index] = PublicDocument{
			path:      document.path,
			mediaType: document.mediaType,
			content:   slices.Clone(document.content),
		}
	}
	return cloned
}
