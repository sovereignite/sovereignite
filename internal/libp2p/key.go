// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package libp2p

import (
	"errors"
	"fmt"
	"reflect"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	cryptopb "github.com/libp2p/go-libp2p/core/crypto/pb"
)

const (
	firstPersistentHandle uint32 = 0x81000000
	lastPersistentHandle  uint32 = 0x81ffffff
)

// ErrPrivateKeyExportProhibited is returned for every attempt to obtain the
// TPM-backed private key material.
var ErrPrivateKeyExportProhibited = errors.New("TPM private key export is prohibited")

// TPMSigningKey is the narrow boundary required from a TPM implementation.
// Implementations must keep the private key inside the TPM for its lifetime,
// verify its Name and immutable signing attributes before returning it, and
// produce signatures accepted by PublicKey().Verify over the exact input
// bytes. In particular, P-256 implementations must apply libp2p's SHA-256 and
// ASN.1 DER signature semantics exactly once.
type TPMSigningKey interface {
	Handle() uint32
	PublicKey() libp2pcrypto.PubKey
	Sign(data []byte) ([]byte, error)
}

// nonExportablePrivateKey adapts a TPM signer to libp2p without providing a
// private Raw representation.
type nonExportablePrivateKey struct {
	key       TPMSigningKey
	handle    uint32
	publicKey libp2pcrypto.PubKey
}

// NewNonExportablePrivateKey returns a libp2p private-key interface backed by
// the injected TPM signer. Its Raw method always fails.
func NewNonExportablePrivateKey(key TPMSigningKey) (libp2pcrypto.PrivKey, error) {
	return newNonExportablePrivateKey(key)
}

func newNonExportablePrivateKey(
	key TPMSigningKey,
) (*nonExportablePrivateKey, error) {
	if isNil(key) {
		return nil, errors.New("TPM signing key is required")
	}
	handle := key.Handle()
	if err := validatePersistentHandle(handle); err != nil {
		return nil, err
	}
	publicKey := key.PublicKey()
	if isNil(publicKey) {
		return nil, errors.New("TPM signing key has no public key")
	}
	switch publicKey.Type() {
	case cryptopb.KeyType_RSA, cryptopb.KeyType_ECDSA:
	default:
		return nil, fmt.Errorf(
			"TPM signing key type %v is not RSA or ECDSA",
			publicKey.Type(),
		)
	}
	if _, err := libp2pcrypto.MarshalPublicKey(publicKey); err != nil {
		return nil, fmt.Errorf("marshal TPM public key: %w", err)
	}
	return &nonExportablePrivateKey{
		key:       key,
		handle:    handle,
		publicKey: publicKey,
	}, nil
}

func (k *nonExportablePrivateKey) Raw() ([]byte, error) {
	return nil, ErrPrivateKeyExportProhibited
}

func (k *nonExportablePrivateKey) Type() cryptopb.KeyType {
	return k.publicKey.Type()
}

func (k *nonExportablePrivateKey) Sign(data []byte) ([]byte, error) {
	signature, err := k.key.Sign(data)
	if err != nil {
		return nil, fmt.Errorf("TPM sign: %w", err)
	}
	return signature, nil
}

func (k *nonExportablePrivateKey) GetPublic() libp2pcrypto.PubKey {
	return k.publicKey
}

func (k *nonExportablePrivateKey) Equals(other libp2pcrypto.Key) bool {
	privateKey, ok := other.(libp2pcrypto.PrivKey)
	if !ok || isNil(privateKey) || isNil(privateKey.GetPublic()) {
		return false
	}
	return k.publicKey.Equals(privateKey.GetPublic())
}

func validatePersistentHandle(handle uint32) error {
	if handle < firstPersistentHandle || handle > lastPersistentHandle {
		return fmt.Errorf(
			"TPM handle 0x%08x is not in the persistent handle range",
			handle,
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
