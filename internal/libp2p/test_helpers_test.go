// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package libp2p

import (
	"context"
	"path/filepath"
	"sync"
	"testing"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

type fakeTPMKey struct {
	handle    uint32
	private   libp2pcrypto.PrivKey
	public    libp2pcrypto.PubKey
	signError error
	signFunc  func([]byte) ([]byte, error)
}

func newFakeTPMKey(t *testing.T, handle uint32) *fakeTPMKey {
	return newFakeTPMKeyOfType(t, handle, libp2pcrypto.ECDSA, -1)
}

func newFakeTPMKeyOfType(
	t *testing.T,
	handle uint32,
	keyType int,
	bits int,
) *fakeTPMKey {
	t.Helper()
	privateKey, publicKey, err := libp2pcrypto.GenerateKeyPair(
		keyType,
		bits,
	)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	return &fakeTPMKey{
		handle:  handle,
		private: privateKey,
		public:  publicKey,
	}
}

func (k *fakeTPMKey) Handle() uint32 {
	return k.handle
}

func (k *fakeTPMKey) PublicKey() libp2pcrypto.PubKey {
	return k.public
}

func (k *fakeTPMKey) Sign(data []byte) ([]byte, error) {
	if k.signFunc != nil {
		return k.signFunc(data)
	}
	if k.signError != nil {
		return nil, k.signError
	}
	return k.private.Sign(data)
}

type hostnameCall struct {
	name string
}

type fakeHostnamectl struct {
	mutex sync.Mutex
	calls []hostnameCall
	err   error
}

type hostnamectlFunc func(context.Context, string) error

func (function hostnamectlFunc) SetHostname(ctx context.Context, name string) error {
	return function(ctx, name)
}

func (r *fakeHostnamectl) SetHostname(_ context.Context, name string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.calls = append(r.calls, hostnameCall{name: name})
	return r.err
}

func (r *fakeHostnamectl) Calls() []hostnameCall {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return append([]hostnameCall(nil), r.calls...)
}

type fakeRunningHost struct {
	mutex      sync.Mutex
	id         peer.ID
	closeCalls int
	closeError error
}

func (host *fakeRunningHost) ID() peer.ID {
	return host.id
}

func (host *fakeRunningHost) Close() error {
	host.mutex.Lock()
	defer host.mutex.Unlock()
	host.closeCalls++
	return host.closeError
}

func (host *fakeRunningHost) CloseCalls() int {
	host.mutex.Lock()
	defer host.mutex.Unlock()
	return host.closeCalls
}

type fakeHostLauncher struct{}

func (*fakeHostLauncher) Launch(
	_ context.Context,
	identity *Identity,
) (RunningHost, error) {
	return &fakeRunningHost{id: identity.PeerID}, nil
}

type hostLauncherFunc func(context.Context, *Identity) (RunningHost, error)

func (function hostLauncherFunc) Launch(
	ctx context.Context,
	identity *Identity,
) (RunningHost, error) {
	return function(ctx, identity)
}

func testConfig(t *testing.T) Config {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve test root: %v", err)
	}
	return Config{
		StateRoot:   root + "/state",
		RuntimeRoot: root + "/run",
	}
}
