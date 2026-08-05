// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package libp2p

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ipfs/go-cid"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multibase"

	"github.com/sovereignite/sovereignite/internal/shared"
)

func TestDerivePublicIdentityUsesCanonicalLibp2pKeyCID(t *testing.T) {
	t.Parallel()
	key := newFakeTPMKey(t, firstPersistentHandle+10)
	identity, err := DerivePublicIdentity(key.Handle(), key.PublicKey())
	if err != nil {
		t.Fatalf("derive public identity: %v", err)
	}
	if strings.HasPrefix(identity.Name, "/ipns/") {
		t.Fatalf("canonical name includes /ipns/ prefix: %q", identity.Name)
	}
	if identity.Name != strings.ToLower(identity.Name) {
		t.Fatalf("canonical name is not lowercase: %q", identity.Name)
	}
	if len(identity.Name) > 63 {
		t.Fatalf("canonical name length = %d, want at most 63", len(identity.Name))
	}
	encoding, _, err := multibase.Decode(identity.Name)
	if err != nil {
		t.Fatalf("decode canonical name multibase: %v", err)
	}
	if encoding != multibase.Base36 {
		t.Fatalf("canonical name base = %v, want base36", encoding)
	}
	decoded, err := cid.Decode(identity.Name)
	if err != nil {
		t.Fatalf("decode canonical name CID: %v", err)
	}
	if decoded.Version() != 1 {
		t.Fatalf("CID version = %d, want 1", decoded.Version())
	}
	if decoded.Type() != cid.Libp2pKey {
		t.Fatalf("CID codec = 0x%x, want libp2p-key", decoded.Type())
	}
	decodedPeerID, err := peer.FromCid(decoded)
	if err != nil {
		t.Fatalf("convert canonical name to peer ID: %v", err)
	}
	if decodedPeerID != identity.PeerID {
		t.Fatalf("CID peer ID = %q, want %q", decodedPeerID, identity.PeerID)
	}
}

func TestDerivePublicIdentitySupportsP256PublicKey(t *testing.T) {
	t.Parallel()
	key := newFakeTPMKeyOfType(
		t,
		firstPersistentHandle+14,
		libp2pcrypto.ECDSA,
		-1,
	)
	identity, err := DerivePublicIdentity(key.Handle(), key.PublicKey())
	if err != nil {
		t.Fatalf("derive P-256 public identity: %v", err)
	}
	decoded, err := cid.Decode(identity.Name)
	if err != nil {
		t.Fatalf("decode P-256 canonical name: %v", err)
	}
	if decoded.Version() != 1 || decoded.Type() != cid.Libp2pKey {
		t.Fatalf("P-256 canonical name is not a CIDv1 libp2p-key: %s", decoded)
	}
	if err := ValidateHostnameLabel(identity.Name); err != nil {
		t.Fatalf("P-256 canonical name is not a valid hostname: %v", err)
	}
}

func TestInitializePersistsOnlyPublicIdentityAndReopensStable(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	key := newFakeTPMKey(t, firstPersistentHandle+11)
	hostnamectl := &fakeHostnamectl{}

	first, err := Initialize(context.Background(), config, key, hostnamectl)
	if err != nil {
		t.Fatalf("initialize identity: %v", err)
	}
	second, err := Initialize(context.Background(), config, key, hostnamectl)
	if err != nil {
		t.Fatalf("reopen identity: %v", err)
	}
	if first.Name != second.Name || first.PeerID != second.PeerID {
		t.Fatalf(
			"identity changed across reopen: first %q/%q, second %q/%q",
			first.Name,
			first.PeerID,
			second.Name,
			second.PeerID,
		)
	}
	if calls := hostnamectl.Calls(); len(calls) != 2 {
		t.Fatalf("hostnamectl call count = %d, want 2", len(calls))
	}

	content, err := os.ReadFile(config.statePath())
	if err != nil {
		t.Fatalf("read identity state: %v", err)
	}
	var state map[string]any
	if err := json.Unmarshal(content, &state); err != nil {
		t.Fatalf("decode identity state: %v", err)
	}
	expectedFields := []string{"version", "tpm_handle", "public_key", "peer_id", "name"}
	if len(state) != len(expectedFields) {
		t.Fatalf("identity state field count = %d, want %d", len(state), len(expectedFields))
	}
	for _, field := range expectedFields {
		if _, ok := state[field]; !ok {
			t.Errorf("identity state missing %q", field)
		}
	}
	privateRaw, err := key.private.Raw()
	if err != nil {
		t.Fatalf("read test-only private key: %v", err)
	}
	if strings.Contains(string(content), base64.StdEncoding.EncodeToString(privateRaw)) {
		t.Fatal("identity state contains serialized private key material")
	}
	if strings.Contains(string(content), "/ipns/") {
		t.Fatal("identity state contains a non-canonical /ipns/ prefix")
	}
	info, err := os.Stat(config.statePath())
	if err != nil {
		t.Fatalf("stat identity state: %v", err)
	}
	if permissions := info.Mode().Perm(); permissions != 0o600 {
		t.Fatalf("identity state permissions = %o, want 600", permissions)
	}
	rootInfo, err := os.Stat(config.StateRoot)
	if err != nil {
		t.Fatalf("stat identity state root: %v", err)
	}
	if permissions := rootInfo.Mode().Perm(); permissions != 0o700 {
		t.Fatalf("identity state root permissions = %o, want 700", permissions)
	}
}

func TestInitializePersistsIdentityBeforeSettingHostname(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	called := false
	runner := hostnamectlFunc(func(_ context.Context, _ string) error {
		called = true
		if _, err := os.ReadFile(config.statePath()); err != nil {
			return errors.New("hostnamectl called before stable identity was persisted")
		}
		return nil
	})
	if _, err := Initialize(
		context.Background(),
		config,
		newFakeTPMKey(t, firstPersistentHandle+12),
		runner,
	); err != nil {
		t.Fatalf("initialize identity: %v", err)
	}
	if !called {
		t.Fatal("hostnamectl was not called")
	}
}

func TestInitializeProvesSignerBeforeAnyPersistentMutation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		configure func(t *testing.T, key *fakeTPMKey)
	}{
		{
			name: "signing failure",
			configure: func(_ *testing.T, key *fakeTPMKey) {
				key.signError = errors.New("TPM signing unavailable")
			},
		},
		{
			name: "mismatched public key",
			configure: func(t *testing.T, key *fakeTPMKey) {
				key.public = newFakeTPMKey(
					t,
					key.handle,
				).public
			},
		},
		{
			name: "invalid signature",
			configure: func(_ *testing.T, key *fakeTPMKey) {
				key.signFunc = func([]byte) ([]byte, error) {
					return []byte("not a valid signature"), nil
				}
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config := testConfig(t)
			key := newFakeTPMKey(t, firstPersistentHandle+15)
			test.configure(t, key)
			hostnamectl := &fakeHostnamectl{}
			if _, err := Initialize(
				context.Background(),
				config,
				key,
				hostnamectl,
			); err == nil {
				t.Fatal("unusable TPM signer was accepted")
			}
			if calls := hostnamectl.Calls(); len(calls) != 0 {
				t.Fatalf("hostnamectl called %d times before signer proof", len(calls))
			}
			if _, err := os.Stat(config.StateRoot); !errors.Is(
				err,
				os.ErrNotExist,
			) {
				t.Fatalf("state root exists after failed signer proof: %v", err)
			}
		})
	}
}

func TestInitializeProvesP256SignerBeforePersistence(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	key := newFakeTPMKeyOfType(
		t,
		firstPersistentHandle+16,
		libp2pcrypto.ECDSA,
		-1,
	)
	if _, err := Initialize(
		context.Background(),
		config,
		key,
		&fakeHostnamectl{},
	); err != nil {
		t.Fatalf("initialize P-256 identity with proof of possession: %v", err)
	}
	if _, err := os.Stat(config.statePath()); err != nil {
		t.Fatalf("P-256 identity state was not persisted: %v", err)
	}
}

func TestInitializeUsesFreshDomainSeparatedProofChallenges(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	key := newFakeTPMKey(t, firstPersistentHandle+17)
	var challenges [][]byte
	key.signFunc = func(challenge []byte) ([]byte, error) {
		challenges = append(challenges, append([]byte(nil), challenge...))
		return key.private.Sign(challenge)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := Initialize(
			context.Background(),
			config,
			key,
			&fakeHostnamectl{},
		); err != nil {
			t.Fatalf("initialize attempt %d: %v", attempt+1, err)
		}
	}
	if len(challenges) != 2 {
		t.Fatalf("proof challenge count = %d, want 2", len(challenges))
	}
	for _, challenge := range challenges {
		if !bytes.HasPrefix(challenge, []byte(identityProofDomain)) {
			t.Fatal("identity proof challenge lacks its domain separator")
		}
	}
	if bytes.Equal(challenges[0], challenges[1]) {
		t.Fatal("identity proof challenge was reused")
	}
}

func TestInitializeRejectsTypedNilHostnameRunnerBeforePersistence(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	var hostnamectl *fakeHostnamectl
	if _, err := Initialize(
		context.Background(),
		config,
		newFakeTPMKey(t, firstPersistentHandle+13),
		hostnamectl,
	); err == nil {
		t.Fatal("typed-nil hostnamectl runner was accepted")
	}
	if _, err := os.Stat(config.statePath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("identity state exists after rejecting hostname runner: %v", err)
	}
}

func TestInitializeRejectsReopenMismatchBeforeHostnameChange(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		mismatched func(t *testing.T, original *fakeTPMKey) *fakeTPMKey
	}{
		{
			name: "handle",
			mismatched: func(_ *testing.T, original *fakeTPMKey) *fakeTPMKey {
				return &fakeTPMKey{
					handle:  original.handle + 1,
					private: original.private,
					public:  original.public,
				}
			},
		},
		{
			name: "public key",
			mismatched: func(t *testing.T, original *fakeTPMKey) *fakeTPMKey {
				replacement := newFakeTPMKey(t, original.handle)
				return replacement
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config := testConfig(t)
			original := newFakeTPMKey(t, firstPersistentHandle+20)
			if _, err := Initialize(
				context.Background(),
				config,
				original,
				&fakeHostnamectl{},
			); err != nil {
				t.Fatalf("initialize original identity: %v", err)
			}
			hostnamectl := &fakeHostnamectl{}
			_, err := Initialize(
				context.Background(),
				config,
				test.mismatched(t, original),
				hostnamectl,
			)
			if !errors.Is(err, ErrIdentityMismatch) {
				t.Fatalf("reopen error = %v, want identity mismatch", err)
			}
			if calls := hostnamectl.Calls(); len(calls) != 0 {
				t.Fatalf("hostnamectl called %d times after mismatch", len(calls))
			}
		})
	}
}

func TestInitializeDoesNotOverwriteMalformedState(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	if err := os.MkdirAll(config.StateRoot, 0o700); err != nil {
		t.Fatalf("create state root: %v", err)
	}
	malformed := []byte("{not-json\n")
	if err := os.WriteFile(config.statePath(), malformed, 0o600); err != nil {
		t.Fatalf("write malformed state: %v", err)
	}
	hostnamectl := &fakeHostnamectl{}
	if _, err := Initialize(
		context.Background(),
		config,
		newFakeTPMKey(t, firstPersistentHandle+30),
		hostnamectl,
	); err == nil {
		t.Fatal("malformed identity state was accepted")
	}
	content, err := os.ReadFile(config.statePath())
	if err != nil {
		t.Fatalf("read malformed state after initialize: %v", err)
	}
	if string(content) != string(malformed) {
		t.Fatal("malformed identity state was overwritten")
	}
	if calls := hostnamectl.Calls(); len(calls) != 0 {
		t.Fatalf("hostnamectl called %d times for malformed state", len(calls))
	}
}

func TestInitializeRejectsSymlinkedStateRoot(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	base := filepath.Dir(config.StateRoot)
	target := filepath.Join(base, "state-target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("create symlink target: %v", err)
	}
	link := filepath.Join(base, "state-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("create state-root symlink: %v", err)
	}
	config.StateRoot = filepath.Join(link, "identity")
	hostnamectl := &fakeHostnamectl{}
	if _, err := Initialize(
		context.Background(),
		config,
		newFakeTPMKey(t, firstPersistentHandle+31),
		hostnamectl,
	); err == nil {
		t.Fatal("symlinked state root was accepted")
	}
	if calls := hostnamectl.Calls(); len(calls) != 0 {
		t.Fatalf("hostnamectl called %d times for symlinked state root", len(calls))
	}
	if _, err := os.Stat(filepath.Join(target, "identity")); !errors.Is(
		err,
		os.ErrNotExist,
	) {
		t.Fatalf("write escaped through state-root symlink: %v", err)
	}
}

func TestInitializeRejectsSymlinkedIdentityStateFile(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	if err := os.MkdirAll(config.StateRoot, 0o700); err != nil {
		t.Fatalf("create state root: %v", err)
	}
	target := filepath.Join(filepath.Dir(config.StateRoot), "identity-target.json")
	original := []byte("do not overwrite\n")
	if err := os.WriteFile(target, original, 0o600); err != nil {
		t.Fatalf("write identity symlink target: %v", err)
	}
	if err := os.Symlink(target, config.statePath()); err != nil {
		t.Fatalf("create identity-state symlink: %v", err)
	}
	hostnamectl := &fakeHostnamectl{}
	if _, err := Initialize(
		context.Background(),
		config,
		newFakeTPMKey(t, firstPersistentHandle+33),
		hostnamectl,
	); err == nil {
		t.Fatal("symlinked identity state file was accepted")
	}
	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read identity symlink target: %v", err)
	}
	if string(content) != string(original) {
		t.Fatal("identity symlink target was overwritten")
	}
	if calls := hostnamectl.Calls(); len(calls) != 0 {
		t.Fatalf("hostnamectl called %d times for symlinked state", len(calls))
	}
}

func TestInitializeRejectsPermissiveExistingState(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	key := newFakeTPMKey(t, firstPersistentHandle+32)
	if _, err := Initialize(
		context.Background(),
		config,
		key,
		&fakeHostnamectl{},
	); err != nil {
		t.Fatalf("initialize identity: %v", err)
	}
	if err := os.Chmod(config.statePath(), 0o644); err != nil {
		t.Fatalf("make identity state permissive: %v", err)
	}
	hostnamectl := &fakeHostnamectl{}
	if _, err := Initialize(
		context.Background(),
		config,
		key,
		hostnamectl,
	); err == nil {
		t.Fatal("permissive existing identity state was accepted")
	}
	if calls := hostnamectl.Calls(); len(calls) != 0 {
		t.Fatalf("hostnamectl called %d times for permissive state", len(calls))
	}
}

func TestInitializeRejectsPermissiveStateRootWithoutChangingMode(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	if err := os.MkdirAll(config.StateRoot, 0o700); err != nil {
		t.Fatalf("create state root: %v", err)
	}
	if err := os.Chmod(config.StateRoot, 0o755); err != nil {
		t.Fatalf("make state root permissive: %v", err)
	}
	hostnamectl := &fakeHostnamectl{}
	if _, err := Initialize(
		context.Background(),
		config,
		newFakeTPMKey(t, firstPersistentHandle+34),
		hostnamectl,
	); err == nil {
		t.Fatal("permissive state root was accepted")
	}
	info, err := os.Stat(config.StateRoot)
	if err != nil {
		t.Fatalf("stat rejected state root: %v", err)
	}
	if permissions := info.Mode().Perm(); permissions != 0o755 {
		t.Fatalf("state root permissions changed to %o, want unchanged 755", permissions)
	}
	if _, err := os.Stat(config.statePath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("identity state created in rejected root: %v", err)
	}
	if calls := hostnamectl.Calls(); len(calls) != 0 {
		t.Fatalf("hostnamectl called %d times for rejected state root", len(calls))
	}
}

func TestConcurrentInitializeCreatesExactlyOneStableIdentity(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	keys := []*fakeTPMKey{
		newFakeTPMKey(t, firstPersistentHandle+40),
		newFakeTPMKey(t, firstPersistentHandle+40),
	}
	runners := []*fakeHostnamectl{{}, {}}
	results := make(chan error, len(keys))
	var start sync.WaitGroup
	start.Add(1)
	for index := range keys {
		index := index
		go func() {
			start.Wait()
			_, err := Initialize(
				context.Background(),
				config,
				keys[index],
				runners[index],
			)
			results <- err
		}()
	}
	start.Done()

	successes := 0
	mismatches := 0
	for range keys {
		err := <-results
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrIdentityMismatch):
			mismatches++
		default:
			t.Fatalf("unexpected concurrent initialize error: %v", err)
		}
	}
	if successes != 1 || mismatches != 1 {
		t.Fatalf(
			"concurrent results = %d successes/%d mismatches, want 1/1",
			successes,
			mismatches,
		)
	}
	hostnameCalls := len(runners[0].Calls()) + len(runners[1].Calls())
	if hostnameCalls != 1 {
		t.Fatalf("hostnamectl total call count = %d, want 1", hostnameCalls)
	}
}

func TestConfigValidateRequiresSafeAbsoluteRoots(t *testing.T) {
	t.Parallel()
	valid := testConfig(t)
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	for name, config := range map[string]Config{
		"relative state":  {StateRoot: "state", RuntimeRoot: valid.RuntimeRoot},
		"relative runtime": {StateRoot: valid.StateRoot, RuntimeRoot: "run"},
		"root state":      {StateRoot: string(filepath.Separator), RuntimeRoot: valid.RuntimeRoot},
		"empty runtime":   {StateRoot: valid.StateRoot},
		"same roots":      {StateRoot: valid.StateRoot, RuntimeRoot: valid.StateRoot},
		"runtime in state": {
			StateRoot:   valid.StateRoot,
			RuntimeRoot: filepath.Join(valid.StateRoot, "run"),
		},
	} {
		config := config
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := config.Validate(); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
}

func TestCanonicalTestVectorMatchesDerivePublicIdentity(t *testing.T) {
	t.Parallel()

	if err := shared.ValidateCanonicalTestVector(); err != nil {
		t.Fatalf("shared canonical test vector invalid: %v", err)
	}

	pubKey, err := libp2pcrypto.UnmarshalPublicKey(
		shared.CanonicalTestVectorPublicKeyDER,
	)
	if err != nil {
		t.Fatalf("unmarshal canonical test vector public key: %v", err)
	}

	identity, err := DerivePublicIdentity(0x81000001, pubKey)
	if err != nil {
		t.Fatalf("derive public identity from canonical vector: %v", err)
	}

	if identity.Name != shared.CanonicalTestVectorIPNS {
		t.Fatalf(
			"canonical IPNS = %q, want %q",
			identity.Name,
			shared.CanonicalTestVectorIPNS,
		)
	}
	if identity.PeerID.String() != shared.CanonicalTestVectorPeerID {
		t.Fatalf(
			"peer ID = %q, want %q",
			identity.PeerID,
			shared.CanonicalTestVectorPeerID,
		)
	}
}
