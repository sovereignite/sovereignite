// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package libp2p

import (
	"context"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"strings"

	"github.com/ipfs/go-cid"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multibase"
)

const identityProofDomain = "github.com/sovereignite/sovereignite/libp2p-identity-proof/v1\x00"

// PublicIdentity is the non-secret, lifetime-stable identity derived from the
// TPM-resident signing key.
type PublicIdentity struct {
	TPMHandle uint32
	PublicKey libp2pcrypto.PubKey
	PeerID    peer.ID
	Name      string
}

// Identity pairs public identity metadata with a non-exportable private-key
// adapter.
type Identity struct {
	PublicIdentity
	privateKey libp2pcrypto.PrivKey
}

// PrivateKey returns a libp2p private-key adapter. Its Raw method and
// crypto.MarshalPrivateKey always return ErrPrivateKeyExportProhibited.
func (i *Identity) PrivateKey() libp2pcrypto.PrivKey {
	if i == nil {
		return nil
	}
	return i.privateKey
}

// DerivePublicIdentity derives both the peer ID and canonical external IPNS
// name without accessing private key material.
func DerivePublicIdentity(
	handle uint32,
	publicKey libp2pcrypto.PubKey,
) (PublicIdentity, error) {
	if err := validatePersistentHandle(handle); err != nil {
		return PublicIdentity{}, err
	}
	if isNil(publicKey) {
		return PublicIdentity{}, errors.New("public key is required")
	}
	if _, err := libp2pcrypto.MarshalPublicKey(publicKey); err != nil {
		return PublicIdentity{}, fmt.Errorf("marshal public key: %w", err)
	}
	peerID, err := peer.IDFromPublicKey(publicKey)
	if err != nil {
		return PublicIdentity{}, fmt.Errorf("derive peer ID: %w", err)
	}
	keyCID := peer.ToCid(peerID)
	if !keyCID.Defined() || keyCID.Version() != 1 ||
		keyCID.Type() != cid.Libp2pKey {
		return PublicIdentity{}, errors.New("derive CIDv1 libp2p-key identifier")
	}
	name, err := keyCID.StringOfBase(multibase.Base36)
	if err != nil {
		return PublicIdentity{}, fmt.Errorf("encode libp2p-key CID as base36: %w", err)
	}
	if name != strings.ToLower(name) || strings.HasPrefix(name, "/ipns/") {
		return PublicIdentity{}, errors.New("derived IPNS identifier is not canonical")
	}
	if err := ValidateHostnameLabel(name); err != nil {
		return PublicIdentity{}, fmt.Errorf(
			"canonical IPNS identifier is not a hostname label: %w",
			err,
		)
	}
	return PublicIdentity{
		TPMHandle: handle,
		PublicKey: publicKey,
		PeerID:    peerID,
		Name:      name,
	}, nil
}

// Initialize derives and persists the public identity, verifies any existing
// state, and only then sets the validated canonical name as the hostname.
func Initialize(
	ctx context.Context,
	config Config,
	key TPMSigningKey,
	hostnameSetter HostnameSetter,
) (*Identity, error) {
	if isNil(ctx) {
		return nil, errors.New("context is required")
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if isNil(hostnameSetter) {
		return nil, errors.New("hostname setter is required")
	}
	identity, err := prepareIdentity(ctx, key)
	if err != nil {
		return nil, err
	}
	if err := activateIdentity(ctx, config, identity, hostnameSetter); err != nil {
		return nil, err
	}
	return identity, nil
}

func prepareIdentity(
	ctx context.Context,
	key TPMSigningKey,
) (*Identity, error) {
	if isNil(ctx) {
		return nil, errors.New("context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	privateKey, err := newNonExportablePrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := proveSigningKey(ctx, privateKey); err != nil {
		return nil, err
	}
	publicIdentity, err := DerivePublicIdentity(
		privateKey.handle,
		privateKey.GetPublic(),
	)
	if err != nil {
		return nil, err
	}
	return &Identity{
		PublicIdentity: publicIdentity,
		privateKey:     privateKey,
	}, nil
}

func activateIdentity(
	ctx context.Context,
	config Config,
	identity *Identity,
	hostnameSetter HostnameSetter,
) error {
	if isNil(ctx) {
		return errors.New("context is required")
	}
	if err := config.Validate(); err != nil {
		return err
	}
	if isNil(identity) {
		return errors.New("prepared identity is required")
	}
	if isNil(hostnameSetter) {
		return errors.New("hostname setter is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	publicIdentity := identity.PublicIdentity
	record, err := newIdentityRecord(publicIdentity)
	if err != nil {
		return err
	}
	if err := ensureIdentityState(config, record); err != nil {
		return err
	}
	if err := SetValidatedHostname(ctx, hostnameSetter, publicIdentity.Name); err != nil {
		return err
	}
	return nil
}

func proveSigningKey(
	ctx context.Context,
	privateKey libp2pcrypto.PrivKey,
) error {
	random := make([]byte, 32)
	if _, err := cryptorand.Read(random); err != nil {
		return fmt.Errorf("generate TPM identity proof challenge: %w", err)
	}
	challenge := append([]byte(identityProofDomain), random...)
	signature, err := privateKey.Sign(append([]byte(nil), challenge...))
	if err != nil {
		return fmt.Errorf("prove TPM identity signing capability: %w", err)
	}
	valid, err := privateKey.GetPublic().Verify(challenge, signature)
	if err != nil {
		return fmt.Errorf("verify TPM identity proof: %w", err)
	}
	if !valid {
		return errors.New("TPM signer does not match its advertised public key")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}
