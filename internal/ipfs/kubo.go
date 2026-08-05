// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package ipfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"

	"github.com/ipfs/go-cid"
)

const (
	// DAGEntryFile is the only reachable directory entry accepted by the
	// public snapshot validator.
	DAGEntryFile = "file"

	maximumReachableBlocks = 4096
	maximumReachableBytes  = 64 << 20
)

var (
	// ErrFullKuboIntegrationUnavailable is returned by production wiring until
	// D-003 authorizes a maintained full-Kubo external signer integration.
	ErrFullKuboIntegrationUnavailable = errors.New(
		"full Kubo TPM signer integration is unavailable",
	)
	// ErrPublicationPending prevents a different outbox item from overtaking a
	// durably prepared record whose publish result may be uncertain.
	ErrPublicationPending = errors.New(
		"a different IPFS publication is already pending",
	)
)

// NodeDescriptor proves the identity and repository properties required
// before semantic readiness. A Boxo/custom node or a serialized private key is
// rejected even if it implements the method set.
type NodeDescriptor struct {
	Product                  string
	Version                  string
	RepositoryPath           string
	IPNSName                 string
	FullKubo                 bool
	ExternalSigner           bool
	PreSignedRecordInjection bool
	PrivateKeySerialized     bool
}

// ImportedSnapshot identifies a complete immutable directory DAG.
type ImportedSnapshot struct {
	Root cid.Cid
}

// DAGBlock is one block reported as reachable from an inspected root.
type DAGBlock struct {
	CID   cid.Cid
	Bytes []byte
}

// Clone returns a deep copy.
func (b DAGBlock) Clone() DAGBlock {
	b.Bytes = slices.Clone(b.Bytes)
	return b
}

// InspectedFile is one decoded reachable directory entry.
type InspectedFile struct {
	Path      string
	MediaType string
	Type      string
	Content   []byte
}

// SnapshotInspection is a complete decoded inventory of the DAG reachable
// from Root. The adapter must include every reachable block and entry.
type SnapshotInspection struct {
	Root   cid.Cid
	Files  []InspectedFile
	Blocks []DAGBlock
}

// FullKuboNode is the smallest product-node injection seam authorized while
// D-003 remains open. Implementations must wrap a full Kubo node, not replace
// it with Boxo or a custom node. It deliberately exposes no arbitrary add,
// filesystem import, mutable write, key generation, or private-key API.
type FullKuboNode interface {
	Describe(context.Context) (NodeDescriptor, error)
	ImportPublicSnapshot(context.Context, PublicSnapshot) (ImportedSnapshot, error)
	InspectPublicSnapshot(context.Context, cid.Cid) (SnapshotInspection, error)
	PinPublicSnapshot(context.Context, cid.Cid) error
	PublicSnapshotPinned(context.Context, cid.Cid) (bool, error)
	PublishSignedRecord(context.Context, SignedRecord) error
	Close() error
}

func validateNodeDescriptor(
	descriptor NodeDescriptor,
	config Config,
	signer *TPMIPNSSigner,
) error {
	if descriptor.Product != "kubo" || !descriptor.FullKubo {
		return errors.New("publication node is not full Kubo")
	}
	if descriptor.Version == "" {
		return errors.New("Kubo node version is required")
	}
	if !descriptor.ExternalSigner ||
		!descriptor.PreSignedRecordInjection {
		return errors.New(
			"Kubo node lacks coherent external pre-signed record injection",
		)
	}
	if descriptor.PrivateKeySerialized {
		return errors.New("Kubo node serialized a TPM-claimed private key")
	}
	if filepath.Clean(descriptor.RepositoryPath) !=
		filepath.Clean(config.RepositoryPath) {
		return errors.New("Kubo node uses the wrong persistent repository")
	}
	if descriptor.IPNSName != signer.Name() {
		return errors.New("Kubo and TPM signer identities are inconsistent")
	}
	return nil
}

func validateImportedSnapshot(
	imported ImportedSnapshot,
	snapshot PublicSnapshot,
	inspection SnapshotInspection,
) error {
	if !imported.Root.Defined() ||
		imported.Root.Version() != 1 ||
		imported.Root.Type() != cid.DagProtobuf {
		return errors.New(
			"imported public snapshot root is not a CIDv1 DAG-PB directory",
		)
	}
	if !inspection.Root.Defined() ||
		!inspection.Root.Equals(imported.Root) {
		return errors.New("inspected DAG has the wrong root CID")
	}
	if len(inspection.Blocks) == 0 ||
		len(inspection.Blocks) > maximumReachableBlocks {
		return errors.New("reachable DAG block count is invalid")
	}
	totalBytes := 0
	rootFound := false
	blocks := make(map[string]struct{}, len(inspection.Blocks))
	for _, block := range inspection.Blocks {
		if !block.CID.Defined() {
			return errors.New("reachable DAG contains an undefined CID")
		}
		key := block.CID.KeyString()
		if _, duplicate := blocks[key]; duplicate {
			return errors.New("reachable DAG repeats a block CID")
		}
		blocks[key] = struct{}{}
		recomputed, err := block.CID.Prefix().Sum(block.Bytes)
		if err != nil || !recomputed.Equals(block.CID) {
			return errors.New("reachable DAG block bytes do not match their CID")
		}
		if block.CID.Equals(imported.Root) {
			rootFound = true
		}
		totalBytes += len(block.Bytes)
		if totalBytes > maximumReachableBytes {
			return errors.New("reachable DAG exceeds its byte limit")
		}
		if containsPrivateKeyPEM(block.Bytes) {
			return errors.New(
				"reachable DAG contains private-key PEM material",
			)
		}
	}
	if !rootFound {
		return errors.New("reachable DAG inventory omits its root block")
	}

	expected := snapshot.Files()
	if len(inspection.Files) != len(expected) {
		return errors.New(
			"reachable DAG file count differs from the complete publication",
		)
	}
	expectedByPath := make(map[string]PublicFile, len(expected))
	for _, file := range expected {
		expectedByPath[file.Path] = file
	}
	seen := make(map[string]struct{}, len(inspection.Files))
	for _, actual := range inspection.Files {
		if actual.Type != DAGEntryFile {
			return errors.New(
				"reachable DAG contains a symlink or non-file entry",
			)
		}
		expectedFile, exists := expectedByPath[actual.Path]
		if !exists {
			return fmt.Errorf(
				"reachable DAG contains undeclared path %q",
				actual.Path,
			)
		}
		if _, duplicate := seen[actual.Path]; duplicate {
			return errors.New("reachable DAG repeats a public path")
		}
		seen[actual.Path] = struct{}{}
		if actual.MediaType != expectedFile.MediaType ||
			!bytes.Equal(actual.Content, expectedFile.Content) {
			return fmt.Errorf(
				"reachable DAG bytes changed for %q",
				actual.Path,
			)
		}
	}
	return nil
}

func containsPrivateKeyPEM(content []byte) bool {
	upper := bytes.ToUpper(content)
	for _, marker := range [][]byte{
		[]byte("-----BEGIN PRIVATE KEY-----"),
		[]byte("-----BEGIN ENCRYPTED PRIVATE KEY-----"),
		[]byte("-----BEGIN RSA PRIVATE KEY-----"),
		[]byte("-----BEGIN EC PRIVATE KEY-----"),
		[]byte("-----BEGIN OPENSSH PRIVATE KEY-----"),
	} {
		if bytes.Contains(upper, marker) {
			return true
		}
	}
	return false
}

func cloneInspection(inspection SnapshotInspection) SnapshotInspection {
	cloned := SnapshotInspection{
		Root:   inspection.Root,
		Files:  make([]InspectedFile, len(inspection.Files)),
		Blocks: make([]DAGBlock, len(inspection.Blocks)),
	}
	for index, file := range inspection.Files {
		cloned.Files[index] = file
		cloned.Files[index].Content = slices.Clone(file.Content)
	}
	for index, block := range inspection.Blocks {
		cloned.Blocks[index] = block.Clone()
	}
	return cloned
}
