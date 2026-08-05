// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package libp2p

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"

	"crypto/x509"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"

	sovereigntpm "github.com/sovereignite/sovereignite/internal/tpm"
)

// TPMSigningKeyAdapter wraps a TPM backend public object and implements
// TPMSigningKey. It never holds or exposes private key material.
type TPMSigningKeyAdapter struct {
	public   libp2pcrypto.PubKey
	handle   uint32
	backend  sovereigntpm.Backend
	reference sovereigntpm.ObjectReference
}

// NewTPMSigningKeyAdapter constructs a signing-key adapter from a TPM backend
// and its public object. The adapter validates that the handle is persistent
// and that the public key can be converted to a libp2p key.
func NewTPMSigningKeyAdapter(
	backend sovereigntpm.Backend,
	public sovereigntpm.Public,
) (*TPMSigningKeyAdapter, error) {
	if backend == nil {
		return nil, errors.New("TPM backend is required")
	}
	if !public.Handle.IsPersistent() {
		return nil, fmt.Errorf(
			"TPM handle %#x is not persistent",
			uint32(public.Handle),
		)
	}
	if len(public.Name) == 0 {
		return nil, errors.New("TPM public name is empty")
	}
	libp2pKey, err := convertPublicKey(public.PublicKey)
	if err != nil {
		return nil, err
	}
	return &TPMSigningKeyAdapter{
		public:  libp2pKey,
		handle:  uint32(public.Handle),
		backend: backend,
		reference: sovereigntpm.ObjectReference{
			Handle:   public.Handle,
			Name:     public.Name,
			Template: public.Template,
		},
	}, nil
}

// Handle returns the TPM persistent handle.
func (a *TPMSigningKeyAdapter) Handle() uint32 {
	return a.handle
}

// PublicKey returns the libp2p public key.
func (a *TPMSigningKeyAdapter) PublicKey() libp2pcrypto.PubKey {
	return a.public
}

// Sign delegates to the TPM backend, verifying the signing object has not
// been mutated since construction.
func (a *TPMSigningKeyAdapter) Sign(data []byte) ([]byte, error) {
	if a == nil || a.backend == nil {
		return nil, errors.New("TPM signing key adapter is not initialized")
	}
	if len(data) == 0 {
		return nil, errors.New("signing data is required")
	}
	signature, err := a.backend.Sign(
		context.Background(),
		sovereigntpm.SignRequest{
			Object:  a.reference,
			Purpose: sovereigntpm.SignPurposeCertificate,
			Scheme:  a.reference.Template.SigningScheme,
			Hash:    crypto.SHA256,
			Payload: data,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("TPM sign: %w", err)
	}
	return signature, nil
}

func convertPublicKey(key crypto.PublicKey) (libp2pcrypto.PubKey, error) {
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		return libp2pcrypto.ECDSAPublicKeyFromPubKey(*k)
	case *rsa.PublicKey:
		der, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return nil, fmt.Errorf("marshal RSA public key: %w", err)
		}
		return libp2pcrypto.UnmarshalRsaPublicKey(der)
	default:
		return nil, fmt.Errorf(
			"unsupported TPM public key type %T",
			key,
		)
	}
}
