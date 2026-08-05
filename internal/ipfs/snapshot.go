// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package ipfs

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/sovereignite/sovereignite/internal/trust"
)

const (
	pathSPIFFEBundle          = "/spiffe-bundle.json"
	pathOpenIDConfiguration   = "/.well-known/openid-configuration"
	pathDeviceDocument        = "/.well-known/sovereignite/device"
	pathFederationDocument    = "/.well-known/sovereignite/federation"
	pathUpdateManifest        = "/updates/manifest.json"
	mediaTypeJSON             = "application/json"
	mediaTypeOCSP             = "application/ocsp-response"
	mediaTypeCRL              = "application/pkix-crl"
	maximumPublicDocumentSize = 1 << 20
	maximumSnapshotSize       = 4 << 20
	maximumSnapshotDocuments  = 256
	publicationDigestDomain   = "github.com/sovereignite/sovereignite/trust-publication/v1\x00"
)

var (
	certificateIDPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
	compactTimePattern   = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z$`)
)

// PublicFile is one immutable, validated file in the public snapshot. Content
// always returns through a copying boundary.
type PublicFile struct {
	Path      string
	MediaType string
	Content   []byte
}

// Clone returns a deep copy.
func (f PublicFile) Clone() PublicFile {
	f.Content = slices.Clone(f.Content)
	return f
}

// PublicSnapshot is the only input accepted by the Kubo import seam. It can be
// constructed only by revalidating a Trust public-only outbox publication.
type PublicSnapshot struct {
	publicationID string
	digest        string
	ipnsName      string
	stateRevision uint64
	createdAt     time.Time
	files         []PublicFile
}

// NewPublicSnapshot independently revalidates Trust's digest-bound,
// public-only publication before any Kubo import can occur.
func NewPublicSnapshot(
	publication trust.Publication,
	expectedIPNSName string,
) (PublicSnapshot, error) {
	if err := publication.Validate(); err != nil {
		return PublicSnapshot{}, fmt.Errorf(
			"validate Trust publication: %w",
			err,
		)
	}
	if expectedIPNSName == "" {
		return PublicSnapshot{}, errors.New("expected IPNS name is required")
	}
	if err := validateCanonicalIPNSName(expectedIPNSName); err != nil {
		return PublicSnapshot{}, err
	}
	if publication.IPNSName != expectedIPNSName {
		return PublicSnapshot{}, errors.New(
			"publication is bound to the wrong IPNS name",
		)
	}
	if publication.StateRevision == 0 {
		return PublicSnapshot{}, errors.New(
			"publication state revision must be positive",
		)
	}
	if publication.CreatedAt.IsZero() {
		return PublicSnapshot{}, errors.New("publication time is required")
	}
	if len(publication.Documents) == 0 ||
		len(publication.Documents) > maximumSnapshotDocuments {
		return PublicSnapshot{}, errors.New(
			"publication document count is invalid",
		)
	}

	files := make([]PublicFile, len(publication.Documents))
	total := 0
	previousPath := ""
	for index, input := range publication.Documents {
		path := input.Path()
		mediaType := input.MediaType()
		content := input.Content()
		expectedMediaType, err := validateAllowedPath(path)
		if err != nil {
			return PublicSnapshot{}, err
		}
		if mediaType != expectedMediaType {
			return PublicSnapshot{}, fmt.Errorf(
				"public path %q has media type %q, want %q",
				path,
				mediaType,
				expectedMediaType,
			)
		}
		if len(content) == 0 || len(content) > maximumPublicDocumentSize {
			return PublicSnapshot{}, fmt.Errorf(
				"public document %q has an invalid size",
				path,
			)
		}
		rebuilt, err := trust.NewPublicDocument(path, mediaType, content)
		if err != nil {
			return PublicSnapshot{}, fmt.Errorf(
				"revalidate public document %q: %w",
				path,
				err,
			)
		}
		if previousPath != "" && path <= previousPath {
			return PublicSnapshot{}, errors.New(
				"publication paths must be unique and canonically sorted",
			)
		}
		previousPath = path
		total += len(content)
		if total > maximumSnapshotSize {
			return PublicSnapshot{}, errors.New(
				"publication exceeds the public data size limit",
			)
		}
		files[index] = PublicFile{
			Path:      rebuilt.Path(),
			MediaType: rebuilt.MediaType(),
			Content:   rebuilt.Content(),
		}
	}

	digest := publicationDigest(
		publication.IPNSName,
		publication.StateRevision,
		files,
	)
	if publication.ID != digest || publication.Digest != digest {
		return PublicSnapshot{}, errors.New(
			"publication ID or digest does not match its complete content",
		)
	}
	if !isLowerHexDigest(publication.ID) {
		return PublicSnapshot{}, errors.New(
			"publication ID is not a lowercase SHA-256 digest",
		)
	}
	return PublicSnapshot{
		publicationID: publication.ID,
		digest:        publication.Digest,
		ipnsName:      publication.IPNSName,
		stateRevision: publication.StateRevision,
		createdAt:     publication.CreatedAt,
		files:         clonePublicFiles(files),
	}, nil
}

// PublicationID returns the immutable outbox item identifier.
func (s PublicSnapshot) PublicationID() string {
	return s.publicationID
}

// Digest returns the complete public-content digest.
func (s PublicSnapshot) Digest() string {
	return s.digest
}

// IPNSName returns the publication's canonical identity binding.
func (s PublicSnapshot) IPNSName() string {
	return s.ipnsName
}

// StateRevision returns the authoritative Trust revision represented here.
func (s PublicSnapshot) StateRevision() uint64 {
	return s.stateRevision
}

// CreatedAt returns the authoritative outbox creation time.
func (s PublicSnapshot) CreatedAt() time.Time {
	return s.createdAt
}

// Files returns complete, copied public files for a full-Kubo adapter. There is
// no path-based filesystem import or arbitrary add/write method.
func (s PublicSnapshot) Files() []PublicFile {
	return clonePublicFiles(s.files)
}

func validateAllowedPath(path string) (string, error) {
	if path == "" ||
		strings.Contains(path, "\\") ||
		strings.Contains(path, "%") ||
		strings.ContainsRune(path, '\x00') ||
		strings.Contains(path, "?") ||
		strings.Contains(path, "#") ||
		strings.Contains(path, "//") ||
		strings.Contains(path, "/./") ||
		strings.Contains(path, "/../") {
		return "", errors.New("public document path has an invalid form")
	}
	switch path {
	case pathSPIFFEBundle,
		pathOpenIDConfiguration,
		pathDeviceDocument,
		pathFederationDocument,
		pathUpdateManifest:
		return mediaTypeJSON, nil
	}
	if strings.HasPrefix(path, "/ocsp/") {
		identifier := strings.TrimPrefix(path, "/ocsp/")
		if !certificateIDPattern.MatchString(identifier) ||
			path != "/ocsp/"+identifier {
			return "", errors.New("public OCSP path is invalid")
		}
		return mediaTypeOCSP, nil
	}
	if strings.HasPrefix(path, "/crl/") {
		encoded := strings.TrimPrefix(path, "/crl/")
		if !compactTimePattern.MatchString(encoded) {
			return "", errors.New("public CRL path is invalid")
		}
		timestamp, err := time.Parse("20060102T150405Z", encoded)
		if err != nil ||
			timestamp.UTC().Format("20060102T150405Z") != encoded {
			return "", errors.New("public CRL path is not canonical")
		}
		return mediaTypeCRL, nil
	}
	if strings.HasPrefix(path, "/device/") &&
		strings.HasSuffix(path, "/identity") {
		identifier := strings.TrimSuffix(
			strings.TrimPrefix(path, "/device/"),
			"/identity",
		)
		peerID, err := peer.Decode(identifier)
		if err != nil ||
			peerID.String() != identifier ||
			path != "/device/"+identifier+"/identity" {
			return "", errors.New(
				"public device identity path is invalid",
			)
		}
		return mediaTypeJSON, nil
	}
	return "", errors.New("public document path is outside the v5 allowlist")
}

func publicationDigest(
	ipnsName string,
	revision uint64,
	files []PublicFile,
) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte(publicationDigestDomain))
	writeDigestField(digest, []byte(ipnsName))
	var revisionBytes [8]byte
	binary.BigEndian.PutUint64(revisionBytes[:], revision)
	_, _ = digest.Write(revisionBytes[:])
	for _, file := range files {
		writeDigestField(digest, []byte(file.Path))
		writeDigestField(digest, []byte(file.MediaType))
		writeDigestField(digest, file.Content)
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

func isLowerHexDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil &&
		hex.EncodeToString(decoded) == value
}

func clonePublicFiles(files []PublicFile) []PublicFile {
	if files == nil {
		return nil
	}
	cloned := make([]PublicFile, len(files))
	for index, file := range files {
		cloned[index] = file.Clone()
	}
	return cloned
}
