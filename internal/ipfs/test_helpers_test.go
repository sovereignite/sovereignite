// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package ipfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/ipfs/go-cid"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"

	"github.com/sovereignite/sovereignite/internal/trust"
)

type testTPMKey struct {
	handle    uint32
	private   libp2pcrypto.PrivKey
	public    libp2pcrypto.PubKey
	signError error
}

func newTestSigner(t *testing.T) *TPMIPNSSigner {
	t.Helper()
	privateKey, publicKey, err := libp2pcrypto.GenerateKeyPair(
		libp2pcrypto.Ed25519,
		-1,
	)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	signer, err := NewTPMIPNSSigner(&testTPMKey{
		handle:  0x81000031,
		private: privateKey,
		public:  publicKey,
	})
	if err != nil {
		t.Fatalf("create test signer: %v", err)
	}
	return signer
}

func (k *testTPMKey) Handle() uint32 {
	return k.handle
}

func (k *testTPMKey) PublicKey() libp2pcrypto.PubKey {
	return k.public
}

func (k *testTPMKey) Sign(data []byte) ([]byte, error) {
	if k.signError != nil {
		return nil, k.signError
	}
	return k.private.Sign(data)
}

func testPublication(
	t *testing.T,
	signer *TPMIPNSSigner,
	revision uint64,
	suffix string,
) trust.Publication {
	t.Helper()
	certificateID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	paths := []struct {
		path      string
		mediaType string
		content   []byte
	}{
		{
			path:      pathSPIFFEBundle,
			mediaType: mediaTypeJSON,
			content: []byte(
				`{"bundle":"` + suffix + `"}`,
			),
		},
		{
			path:      pathOpenIDConfiguration,
			mediaType: mediaTypeJSON,
			content: []byte(
				`{"issuer":"https://example.invalid/` + suffix + `"}`,
			),
		},
		{
			path:      pathDeviceDocument,
			mediaType: mediaTypeJSON,
			content: []byte(
				`{"device":"` + suffix + `"}`,
			),
		},
		{
			path:      pathFederationDocument,
			mediaType: mediaTypeJSON,
			content: []byte(
				`{"federation":"` + suffix + `"}`,
			),
		},
		{
			path:      "/ocsp/" + certificateID,
			mediaType: mediaTypeOCSP,
			content:   []byte{0x30, 0x01, byte(revision)},
		},
		{
			path:      "/crl/20260728T120000Z",
			mediaType: mediaTypeCRL,
			content:   []byte{0x30, 0x02, byte(revision)},
		},
		{
			path:      pathUpdateManifest,
			mediaType: mediaTypeJSON,
			content: []byte(
				`{"manifest":"` + suffix + `"}`,
			),
		},
		{
			path: "/device/" + signer.PeerID().String() + "/identity",
			mediaType: mediaTypeJSON,
			content: []byte(
				`{"identity":"` + suffix + `"}`,
			),
		},
	}
	documents := make([]trust.PublicDocument, len(paths))
	for index, input := range paths {
		document, err := trust.NewPublicDocument(
			input.path,
			input.mediaType,
			input.content,
		)
		if err != nil {
			t.Fatalf("create public document %q: %v", input.path, err)
		}
		documents[index] = document
	}
	sort.Slice(documents, func(left, right int) bool {
		return documents[left].Path() < documents[right].Path()
	})
	files := make([]PublicFile, len(documents))
	for index, document := range documents {
		files[index] = PublicFile{
			Path:      document.Path(),
			MediaType: document.MediaType(),
			Content:   document.Content(),
		}
	}
	digest := publicationDigest(signer.Name(), revision, files)
	return trust.Publication{
		ID:            digest,
		StateRevision: revision,
		IPNSName:      signer.Name(),
		Digest:        digest,
		Documents:     documents,
		CreatedAt:     time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC),
	}
}

func testCID(t *testing.T, content []byte) cid.Cid {
	t.Helper()
	value, err := (cid.Prefix{
		Version:  1,
		Codec:    cid.Raw,
		MhType:   0x12,
		MhLength: 32,
	}).Sum(content)
	if err != nil {
		t.Fatalf("create test CID: %v", err)
	}
	return value
}

type fakeKuboNode struct {
	mu sync.Mutex

	descriptor NodeDescriptor
	inspections map[string]SnapshotInspection
	pins        map[string]bool
	records     []SignedRecord
	attempts    []SignedRecord
	operations  []string

	importError  error
	inspectError error
	pinError     error
	pinnedError  error
	publishError error
	closeError   error
	closed       bool
	mutate       func(SnapshotInspection) SnapshotInspection
}

func newFakeKuboNode(
	config Config,
	signer *TPMIPNSSigner,
) *fakeKuboNode {
	return &fakeKuboNode{
		descriptor: NodeDescriptor{
			Product:                  "kubo",
			Version:                  "v0.42.0-test",
			RepositoryPath:           config.RepositoryPath,
			IPNSName:                 signer.Name(),
			FullKubo:                 true,
			ExternalSigner:           true,
			PreSignedRecordInjection: true,
		},
		inspections: make(map[string]SnapshotInspection),
		pins:        make(map[string]bool),
	}
}

func (n *fakeKuboNode) Describe(
	context.Context,
) (NodeDescriptor, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.operations = append(n.operations, "describe")
	return n.descriptor, nil
}

func (n *fakeKuboNode) ImportPublicSnapshot(
	_ context.Context,
	snapshot PublicSnapshot,
) (ImportedSnapshot, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.operations = append(n.operations, "import")
	if n.importError != nil {
		return ImportedSnapshot{}, n.importError
	}
	var rootData bytes.Buffer
	_, _ = rootData.WriteString("test-full-kubo-directory-v1\x00")
	_, _ = rootData.WriteString(snapshot.Digest())
	inspection := SnapshotInspection{}
	for _, file := range snapshot.Files() {
		contentCID := testCIDValue(file.Content)
		_, _ = rootData.WriteString(file.Path)
		_, _ = rootData.Write(contentCID.Bytes())
		inspection.Files = append(inspection.Files, InspectedFile{
			Path:      file.Path,
			MediaType: file.MediaType,
			Type:      DAGEntryFile,
			Content:   append([]byte(nil), file.Content...),
		})
		inspection.Blocks = append(
			inspection.Blocks,
			DAGBlock{CID: contentCID, Bytes: append([]byte(nil), file.Content...)},
		)
	}
	root := testCIDValueWithCodec(rootData.Bytes(), cid.DagProtobuf)
	inspection.Root = root
	inspection.Blocks = append(
		inspection.Blocks,
		DAGBlock{CID: root, Bytes: append([]byte(nil), rootData.Bytes()...)},
	)
	n.inspections[root.KeyString()] = cloneInspection(inspection)
	return ImportedSnapshot{Root: root}, nil
}

func (n *fakeKuboNode) InspectPublicSnapshot(
	_ context.Context,
	root cid.Cid,
) (SnapshotInspection, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.operations = append(n.operations, "inspect")
	if n.inspectError != nil {
		return SnapshotInspection{}, n.inspectError
	}
	inspection, exists := n.inspections[root.KeyString()]
	if !exists {
		return SnapshotInspection{}, errors.New("test DAG not found")
	}
	inspection = cloneInspection(inspection)
	if n.mutate != nil {
		inspection = n.mutate(inspection)
	}
	return inspection, nil
}

func (n *fakeKuboNode) PinPublicSnapshot(
	_ context.Context,
	root cid.Cid,
) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.operations = append(n.operations, "pin")
	if n.pinError != nil {
		return n.pinError
	}
	n.pins[root.KeyString()] = true
	return nil
}

func (n *fakeKuboNode) PublicSnapshotPinned(
	_ context.Context,
	root cid.Cid,
) (bool, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.operations = append(n.operations, "pinned")
	if n.pinnedError != nil {
		return false, n.pinnedError
	}
	return n.pins[root.KeyString()], nil
}

func (n *fakeKuboNode) PublishSignedRecord(
	_ context.Context,
	record SignedRecord,
) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.operations = append(n.operations, "publish")
	n.attempts = append(n.attempts, record.Clone())
	if n.publishError != nil {
		return n.publishError
	}
	n.records = append(n.records, record.Clone())
	return nil
}

func (n *fakeKuboNode) Ready(context.Context) error {
	return nil
}

func (n *fakeKuboNode) Done() <-chan error {
	ch := make(chan error)
	return ch
}

func (n *fakeKuboNode) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.operations = append(n.operations, "close")
	n.closed = true
	return n.closeError
}

func testCIDValue(content []byte) cid.Cid {
	return testCIDValueWithCodec(content, cid.Raw)
}

func testCIDValueWithCodec(content []byte, codec uint64) cid.Cid {
	value, err := (cid.Prefix{
		Version:  1,
		Codec:    codec,
		MhType:   0x12,
		MhLength: 32,
	}).Sum(content)
	if err != nil {
		panic(fmt.Sprintf("create test CID: %v", err))
	}
	return value
}

type memoryPublicationStore struct {
	mu sync.Mutex

	state       PublicationState
	commitCount int
	failCommit  map[int]error
}

func newMemoryPublicationStore() *memoryPublicationStore {
	return &memoryPublicationStore{
		state:      emptyPublicationState(),
		failCommit: make(map[int]error),
	}
}

func (s *memoryPublicationStore) Load() (PublicationState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state.Clone(), nil
}

func (s *memoryPublicationStore) Commit(
	expected uint64,
	next PublicationState,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.commitCount++
	if err := s.failCommit[s.commitCount]; err != nil {
		return err
	}
	if s.state.Revision != expected {
		return ErrPublicationStateConflict
	}
	if next.Revision != expected+1 {
		return errors.New("test store revision did not advance")
	}
	s.state = next.Clone()
	return nil
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(duration)
}

func testConfig(t *testing.T) Config {
	t.Helper()
	root := t.TempDir()
	repository := filepath.Join(root, "ipfs")
	runtimePath := filepath.Join(root, "run")
	for _, path := range []string{repository, runtimePath} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatalf("create test directory %q: %v", path, err)
		}
	}
	config := DefaultConfig()
	config.RepositoryPath = repository
	config.RuntimePath = runtimePath
	config.RecordPolicy = RecordPolicy{
		Validity:     time.Hour,
		MaxValidity:  time.Hour,
		MaxStaleness: time.Hour,
		ClockSkew:    time.Minute,
	}
	return config
}
