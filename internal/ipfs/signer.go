// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package ipfs

import (
	"context"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"

	"github.com/ipfs/go-cid"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	cryptopb "github.com/libp2p/go-libp2p/core/crypto/pb"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multibase"
)

const (
	firstPersistentHandle uint32 = 0x81000000
	lastPersistentHandle  uint32 = 0x81ffffff
	signerProofDomain             = "github.com/sovereignite/sovereignite/ipns-signer-proof/v1\x00"
)

var (
	// ErrPrivateKeyExportProhibited is returned by every private-material
	// export surface of TPMIPNSSigner.
	ErrPrivateKeyExportProhibited = errors.New(
		"TPM IPNS private key export is prohibited",
	)
	// ErrKeyManagerSignerUnavailable is the production fail-closed state until
	// D-012 authorizes and supplies the Key Manager signing contract.
	ErrKeyManagerSignerUnavailable = errors.New(
		"Key Manager IPNS signer integration is unavailable",
	)
)

// TPMKey is the narrow, non-inventory-owning Key Manager seam used by IPFS.
// Production implementations must authorize only the lifetime
// device-ipns-identity role. The interface deliberately has no private-key,
// duplication, rotation, creation, or generic export operation.
type TPMKey interface {
	Handle() uint32
	PublicKey() libp2pcrypto.PubKey
	Sign([]byte) ([]byte, error)
}

// TPMIPNSSigner is a libp2p private-key adapter whose signing operation is
// delegated to a persistent TPM key and whose Raw and Export methods always
// fail. It can be used for pre-signed record construction, but stock Kubo
// cannot safely consume it as its complete host identity under D-003.
type TPMIPNSSigner struct {
	key        TPMKey
	handle     uint32
	publicKey  libp2pcrypto.PubKey
	peerID     peer.ID
	name       string
	identifier []byte
	ula        netip.Prefix
}

// NewTPMIPNSSigner validates the persistent handle, public identity, canonical
// IPNS name, and shared deterministic ULA before exposing the signer.
func NewTPMIPNSSigner(key TPMKey) (*TPMIPNSSigner, error) {
	if isNil(key) {
		return nil, errors.New("TPM IPNS key is required")
	}
	handle := key.Handle()
	if handle < firstPersistentHandle || handle > lastPersistentHandle {
		return nil, fmt.Errorf(
			"TPM IPNS handle 0x%08x is not persistent",
			handle,
		)
	}
	publicKey := key.PublicKey()
	if isNil(publicKey) {
		return nil, errors.New("TPM IPNS key has no public key")
	}
	if _, err := libp2pcrypto.MarshalPublicKey(publicKey); err != nil {
		return nil, fmt.Errorf("marshal TPM IPNS public key: %w", err)
	}
	peerID, name, identifier, err := canonicalIdentityForPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	ula, err := ULAForIPNSIdentifier(identifier)
	if err != nil {
		return nil, fmt.Errorf("derive IPNS ULA: %w", err)
	}
	return &TPMIPNSSigner{
		key:        key,
		handle:     handle,
		publicKey:  publicKey,
		peerID:     peerID,
		name:       name,
		identifier: slices.Clone(identifier),
		ula:        ula,
	}, nil
}

// TPMHandle returns the lifetime persistent-handle reference. It never returns
// TPM private or authorization material.
func (s *TPMIPNSSigner) TPMHandle() uint32 {
	if s == nil {
		return 0
	}
	return s.handle
}

// Name returns the lowercase CIDv1/base36 canonical IPNS name without an
// /ipns/ prefix.
func (s *TPMIPNSSigner) Name() string {
	if s == nil {
		return ""
	}
	return s.name
}

// PeerID returns the public-key-derived libp2p peer ID.
func (s *TPMIPNSSigner) PeerID() peer.ID {
	if s == nil {
		return ""
	}
	return s.peerID
}

// CanonicalIdentifier returns the canonical binary CID identity consumed by
// ULAForIPNSIdentifier.
func (s *TPMIPNSSigner) CanonicalIdentifier() []byte {
	if s == nil {
		return nil
	}
	return slices.Clone(s.identifier)
}

// ULA returns the shared, domain-separated deterministic /48.
func (s *TPMIPNSSigner) ULA() netip.Prefix {
	if s == nil {
		return netip.Prefix{}
	}
	return s.ula
}

// Raw always refuses private-key serialization.
func (s *TPMIPNSSigner) Raw() ([]byte, error) {
	return nil, ErrPrivateKeyExportProhibited
}

// Export always refuses every project-level private-key export attempt.
func (s *TPMIPNSSigner) Export() ([]byte, error) {
	return nil, ErrPrivateKeyExportProhibited
}

// Type implements libp2pcrypto.PrivKey without exposing private material.
func (s *TPMIPNSSigner) Type() cryptopb.KeyType {
	if s == nil || isNil(s.publicKey) {
		return cryptopb.KeyType(-1)
	}
	return s.publicKey.Type()
}

// Sign delegates the exact bytes to the injected TPM boundary and verifies
// the returned signature before releasing it.
func (s *TPMIPNSSigner) Sign(data []byte) ([]byte, error) {
	if s == nil || isNil(s.key) || isNil(s.publicKey) {
		return nil, errors.New("TPM IPNS signer is not configured")
	}
	payload := slices.Clone(data)
	signature, err := s.key.Sign(payload)
	if err != nil {
		return nil, fmt.Errorf("TPM IPNS sign: %w", err)
	}
	valid, err := s.publicKey.Verify(payload, signature)
	if err != nil {
		return nil, fmt.Errorf("verify TPM IPNS signature: %w", err)
	}
	if !valid {
		return nil, errors.New(
			"TPM IPNS signer does not match its advertised public key",
		)
	}
	return slices.Clone(signature), nil
}

// SignContext applies cancellation before and after the TPM signing boundary.
func (s *TPMIPNSSigner) SignContext(
	ctx context.Context,
	data []byte,
) ([]byte, error) {
	if isNil(ctx) {
		return nil, errors.New("signing context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	signature, err := s.Sign(data)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return signature, nil
}

func proveIPNSSigner(
	ctx context.Context,
	signer *TPMIPNSSigner,
) error {
	if signer == nil {
		return errors.New("TPM IPNS signer is required")
	}
	random := make([]byte, 32)
	if _, err := cryptorand.Read(random); err != nil {
		return fmt.Errorf("generate IPNS signer proof challenge: %w", err)
	}
	challenge := append([]byte(signerProofDomain), random...)
	if _, err := signer.SignContext(ctx, challenge); err != nil {
		return fmt.Errorf("prove TPM IPNS signing capability: %w", err)
	}
	return nil
}

// GetPublic implements libp2pcrypto.PrivKey.
func (s *TPMIPNSSigner) GetPublic() libp2pcrypto.PubKey {
	if s == nil {
		return nil
	}
	return s.publicKey
}

// Equals compares only public identities.
func (s *TPMIPNSSigner) Equals(other libp2pcrypto.Key) bool {
	if s == nil || isNil(s.publicKey) || isNil(other) {
		return false
	}
	privateKey, ok := other.(libp2pcrypto.PrivKey)
	if !ok || isNil(privateKey) || isNil(privateKey.GetPublic()) {
		return false
	}
	return s.publicKey.Equals(privateKey.GetPublic())
}

func canonicalIdentityForPublicKey(
	publicKey libp2pcrypto.PubKey,
) (peer.ID, string, []byte, error) {
	peerID, err := peer.IDFromPublicKey(publicKey)
	if err != nil {
		return "", "", nil, fmt.Errorf("derive IPNS peer ID: %w", err)
	}
	keyCID := peer.ToCid(peerID)
	if !keyCID.Defined() ||
		keyCID.Version() != 1 ||
		keyCID.Type() != cid.Libp2pKey {
		return "", "", nil, errors.New(
			"public key did not produce a CIDv1 libp2p-key identity",
		)
	}
	name, err := keyCID.StringOfBase(multibase.Base36)
	if err != nil {
		return "", "", nil, fmt.Errorf(
			"encode canonical IPNS name: %w",
			err,
		)
	}
	if err := validateCanonicalIPNSName(name); err != nil {
		return "", "", nil, err
	}
	decoded, err := cid.Decode(name)
	if err != nil || !decoded.Equals(keyCID) {
		return "", "", nil, errors.New(
			"canonical IPNS name does not round-trip to its public key",
		)
	}
	return peerID, name, slices.Clone(keyCID.Bytes()), nil
}

func validateCanonicalIPNSName(name string) error {
	if name == "" {
		return errors.New("canonical IPNS name is required")
	}
	decoded, err := cid.Decode(name)
	if err != nil {
		return fmt.Errorf("decode canonical IPNS name: %w", err)
	}
	if decoded.Version() != 1 || decoded.Type() != cid.Libp2pKey {
		return errors.New("IPNS name must be a CIDv1 libp2p-key")
	}
	canonical, err := decoded.StringOfBase(multibase.Base36)
	if err != nil {
		return fmt.Errorf("encode canonical IPNS name: %w", err)
	}
	if canonical != name {
		return errors.New(
			"IPNS name is not canonical lowercase CIDv1/base36",
		)
	}
	return nil
}

func isNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

var _ libp2pcrypto.PrivKey = (*TPMIPNSSigner)(nil)
