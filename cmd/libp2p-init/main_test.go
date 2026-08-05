// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"

	identity "github.com/sovereignite/sovereignite/internal/libp2p"
)

func isListenerClosedError(err error) bool {
	return strings.Contains(err.Error(), "closed network connection")
}

type commandTestKey struct {
	handle  uint32
	private libp2pcrypto.PrivKey
	public  libp2pcrypto.PubKey
}

func newCommandTestKey(t *testing.T, handle uint32) *commandTestKey {
	t.Helper()
	privateKey, publicKey, err := libp2pcrypto.GenerateKeyPair(
		libp2pcrypto.ECDSA,
		-1,
	)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	return &commandTestKey{
		handle:  handle,
		private: privateKey,
		public:  publicKey,
	}
}

func commandTestRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve test root: %v", err)
	}
	return root
}

func (k *commandTestKey) Handle() uint32 {
	return k.handle
}

func (k *commandTestKey) PublicKey() libp2pcrypto.PubKey {
	return k.public
}

func (k *commandTestKey) Sign(data []byte) ([]byte, error) {
	return k.private.Sign(data)
}

type commandHostnamectl struct {
	calls atomic.Int32
}

func (r *commandHostnamectl) SetHostname(context.Context, string) error {
	r.calls.Add(1)
	return nil
}

type commandRunningHost struct {
	id peer.ID
}

func (*commandRunningHost) Close() error {
	return nil
}

func (host *commandRunningHost) ID() peer.ID {
	return host.id
}

type commandHostLauncher struct{}

func (*commandHostLauncher) Launch(
	_ context.Context,
	hostIdentity *identity.Identity,
) (identity.RunningHost, error) {
	return &commandRunningHost{id: hostIdentity.PeerID}, nil
}

func TestRunFailsClosedWithoutTPMProvider(t *testing.T) {
	t.Parallel()
	err := run(
		context.Background(),
		nil,
		defaultDependencies(),
	)
	if !errors.Is(err, errTPMProviderUnavailable) {
		t.Fatalf("run error = %v, want unavailable TPM provider", err)
	}
}

func TestRunRejectsInvalidArgumentsBeforeOpeningProvider(t *testing.T) {
	t.Parallel()
	var opened atomic.Int32
	deps := dependencies{
		openKey: func(context.Context) (identity.TPMSigningKey, error) {
			opened.Add(1)
			return nil, errors.New("unexpected")
		},
		hostnameSetter: &commandHostnamectl{},
	}
	for _, args := range [][]string{
		{"unexpected"},
		{"-state-root", "relative"},
		{"-runtime-root", "relative"},
	} {
		if err := run(context.Background(), args, deps); err == nil {
			t.Fatalf("invalid arguments %v were accepted", args)
		}
	}
	if calls := opened.Load(); calls != 0 {
		t.Fatalf("TPM provider opened %d times for invalid arguments", calls)
	}
}

func TestRunFailsBeforeMutationWhenRealHostIsMissing(t *testing.T) {
	t.Parallel()
	root := commandTestRoot(t)
	stateRoot := filepath.Join(root, "state")
	runtimeRoot := filepath.Join(root, "run")
	key := newCommandTestKey(t, 0x81000002)
	hostnamectl := &commandHostnamectl{}
	err := run(
		context.Background(),
		[]string{
			"-state-root", stateRoot,
			"-runtime-root", runtimeRoot,
		},
		dependencies{
			openKey: func(context.Context) (identity.TPMSigningKey, error) {
				return key, nil
			},
			hostnameSetter: hostnamectl,
		},
	)
	if !errors.Is(err, identity.ErrHostUnavailable) {
		t.Fatalf("run error = %v, want real-host unavailable", err)
	}
	if calls := hostnamectl.calls.Load(); calls != 0 {
		t.Fatalf("hostnamectl call count = %d, want 0", calls)
	}
	for _, path := range []string{stateRoot, runtimeRoot} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("metadata path %q exists without a real host: %v", path, err)
		}
	}
}

func TestRunServesUntilContextCancellation(t *testing.T) {
	t.Parallel()
	root := commandTestRoot(t)
	stateRoot := filepath.Join(root, "state")
	runtimeRoot := filepath.Join(root, "run")
	key := newCommandTestKey(t, 0x81000001)
	hostnamectl := &commandHostnamectl{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	result := make(chan error, 1)
	go func() {
		result <- run(
			ctx,
			[]string{
				"-state-root", stateRoot,
				"-runtime-root", runtimeRoot,
			},
			dependencies{
				openKey: func(context.Context) (identity.TPMSigningKey, error) {
					return key, nil
				},
				hostLauncher: &commandHostLauncher{},
				hostnameSetter: hostnamectl,
			},
		)
	}()

	endpointPath := filepath.Join(runtimeRoot, "endpoint.json")
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(endpointPath); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stat endpoint: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatal("endpoint was not published")
		}
		time.Sleep(5 * time.Millisecond)
	}
	select {
	case err := <-result:
		t.Fatalf("run stopped before cancellation: %v", err)
	default:
	}
	cancel()
	select {
	case err := <-result:
		if err != nil && !isListenerClosedError(err) {
			t.Fatalf("run after cancellation: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("run did not stop after cancellation")
	}
	if calls := hostnamectl.calls.Load(); calls != 1 {
		t.Fatalf("hostnamectl call count = %d, want 1", calls)
	}
	if _, err := os.Stat(endpointPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("endpoint remains after command shutdown: %v", err)
	}
}
