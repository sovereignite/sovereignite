// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ipfs/go-cid"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"

	"github.com/sovereignite/sovereignite/internal/ipfs"
)

type commandTPMKey struct {
	private libp2pcrypto.PrivKey
	public  libp2pcrypto.PubKey
}

func newCommandSigner(t *testing.T) *ipfs.TPMIPNSSigner {
	t.Helper()
	privateKey, publicKey, err := libp2pcrypto.GenerateKeyPair(
		libp2pcrypto.Ed25519,
		-1,
	)
	if err != nil {
		t.Fatalf("generate command test key: %v", err)
	}
	signer, err := ipfs.NewTPMIPNSSigner(&commandTPMKey{
		private: privateKey,
		public:  publicKey,
	})
	if err != nil {
		t.Fatalf("create command signer: %v", err)
	}
	return signer
}

func (k *commandTPMKey) Handle() uint32 {
	return 0x81000051
}

func (k *commandTPMKey) PublicKey() libp2pcrypto.PubKey {
	return k.public
}

func (k *commandTPMKey) Sign(data []byte) ([]byte, error) {
	return k.private.Sign(data)
}

type commandNode struct {
	descriptor ipfs.NodeDescriptor
	closed     atomic.Bool
	done       chan error
}

func (n *commandNode) Describe(
	context.Context,
) (ipfs.NodeDescriptor, error) {
	return n.descriptor, nil
}

func (n *commandNode) Ready(context.Context) error {
	return nil
}

func (n *commandNode) Done() <-chan error {
	return n.done
}

func (n *commandNode) ImportPublicSnapshot(
	context.Context,
	ipfs.PublicSnapshot,
) (ipfs.ImportedSnapshot, error) {
	return ipfs.ImportedSnapshot{}, errors.New("unexpected import")
}

func (n *commandNode) InspectPublicSnapshot(
	context.Context,
	cid.Cid,
) (ipfs.SnapshotInspection, error) {
	return ipfs.SnapshotInspection{}, errors.New("unexpected inspect")
}

func (n *commandNode) PinPublicSnapshot(context.Context, cid.Cid) error {
	return errors.New("unexpected pin")
}

func (n *commandNode) PublicSnapshotPinned(
	context.Context,
	cid.Cid,
) (bool, error) {
	return false, errors.New("unexpected pin query")
}

func (n *commandNode) PublishSignedRecord(
	context.Context,
	ipfs.SignedRecord,
) error {
	return errors.New("unexpected publish")
}

func (n *commandNode) Close() error {
	n.closed.Store(true)
	return nil
}

func TestRunFailsClosedWithoutKeyManagerSigner(t *testing.T) {
	t.Parallel()
	err := run(
		context.Background(),
		nil,
		defaultDependencies(),
		io.Discard,
	)
	if !errors.Is(err, ipfs.ErrKeyManagerSignerUnavailable) {
		t.Fatalf("run error = %v, want Key Manager signer gate", err)
	}
}

func TestRunFailsClosedWithoutAuthorizedFullKuboIntegration(
	t *testing.T,
) {
	t.Parallel()
	deps := defaultDependencies()
	signer := newCommandSigner(t)
	deps.openSigner = func(
		context.Context,
	) (*ipfs.TPMIPNSSigner, error) {
		return signer, nil
	}
	err := run(context.Background(), nil, deps, io.Discard)
	if !errors.Is(err, ipfs.ErrFullKuboIntegrationUnavailable) {
		t.Fatalf("run error = %v, want full-Kubo gate", err)
	}
}

func TestRunRejectsArgumentsBeforeOpeningDependencies(t *testing.T) {
	t.Parallel()
	var opened atomic.Int32
	deps := dependencies{
		openSigner: func(
			context.Context,
		) (*ipfs.TPMIPNSSigner, error) {
			opened.Add(1)
			return nil, errors.New("unexpected")
		},
	}
	for _, args := range [][]string{
		{"unexpected"},
		{"-repository", "relative"},
		{"-runtime", "relative"},
		{"-record-validity", "0s"},
		{"-record-validity", "1h", "-max-record-validity", "1m"},
	} {
		if err := run(
			context.Background(),
			args,
			deps,
			io.Discard,
		); err == nil {
			t.Fatalf("invalid arguments %v were accepted", args)
		}
	}
	if opened.Load() != 0 {
		t.Fatalf("dependencies opened %d times", opened.Load())
	}
}

func TestRunServesUntilCancellationWithInjectedFullKubo(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	repository := filepath.Join(root, "ipfs")
	runtimePath := filepath.Join(root, "run")
	for _, path := range []string{repository, runtimePath} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatalf("create command directory %q: %v", path, err)
		}
	}
	signer := newCommandSigner(t)
	node := &commandNode{done: make(chan error)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		config := ipfs.DefaultConfig()
		config.RepositoryPath = repository
		config.RuntimePath = runtimePath
		result <- runWithConfig(
			ctx,
			nil,
			dependencies{
				openSigner: func(
					context.Context,
				) (*ipfs.TPMIPNSSigner, error) {
					return signer, nil
				},
				openNode: func(
					_ context.Context,
					config ipfs.Config,
					input *ipfs.TPMIPNSSigner,
				) (ipfs.FullKuboNode, error) {
					node.descriptor = ipfs.NodeDescriptor{
						Product:                  "kubo",
						Version:                  "v0.42.0-test",
						RepositoryPath:           config.RepositoryPath,
						IPNSName:                 input.Name(),
						FullKubo:                 true,
						ExternalSigner:           true,
						PreSignedRecordInjection: true,
					}
					return node, nil
				},
			},
			io.Discard,
			config,
		)
	}()
	readyPath := filepath.Join(runtimePath, "ready.json")
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(readyPath); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("inspect readiness: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatal("IPFS readiness was not published")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("run after cancellation: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("run did not stop after cancellation")
	}
	if !node.closed.Load() {
		t.Fatal("injected full Kubo node was not closed")
	}
	if _, err := os.Stat(readyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("readiness remains after command exit: %v", err)
	}
}
