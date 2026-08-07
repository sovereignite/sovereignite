// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

// Package tpm defines the fail-closed TPM 2.0 boundary used by the key manager.
//
// The boundary deliberately has no method that returns private or sensitive
// object data. Implementations are expected to map Handle and Template to the
// corresponding github.com/google/go-tpm typed API values.
package tpm

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
)

// Handle is a TPM persistent object handle.
type Handle uint32

const (
	// PersistentHandleFirst and PersistentHandleLast bound the TPM 2.0
	// owner-persistent handle range.
	PersistentHandleFirst Handle = 0x81000000
	PersistentHandleLast  Handle = 0x817fffff
)

// IsPersistent reports whether the handle is in the TPM persistent range.
func (h Handle) IsPersistent() bool {
	return h >= PersistentHandleFirst && h <= PersistentHandleLast
}

// Algorithm identifies a requested public-key algorithm and parameter set.
type Algorithm string

const (
	AlgorithmRSA4096   Algorithm = "rsa-4096"
	AlgorithmECDSAP256 Algorithm = "ecdsa-p256"
	AlgorithmEd25519   Algorithm = "ed25519"
)

// HashAlgorithm identifies the TPM public-name hash.
type HashAlgorithm string

const (
	HashSHA256 HashAlgorithm = "sha256"
)

// SignatureScheme identifies the signature encoding expected from the TPM.
type SignatureScheme string

const (
	SchemeRSASSASHA256 SignatureScheme = "rsassa-sha256"
	SchemeECDSASHA256  SignatureScheme = "ecdsa-sha256"
	SchemeEd25519      SignatureScheme = "ed25519"
)

// ObjectAttributes records the security-relevant TPM public attributes.
type ObjectAttributes struct {
	FixedTPM            bool `json:"fixed_tpm"`
	FixedParent         bool `json:"fixed_parent"`
	SensitiveDataOrigin bool `json:"sensitive_data_origin"`
	UserWithAuth        bool `json:"user_with_auth"`
	SignEncrypt         bool `json:"sign_encrypt"`
	NoDA                bool `json:"no_da"`
}

// Template is the public, persistable description of a TPM signing key.
//
// It intentionally contains no auth value, seed, private blob, sensitive area,
// duplication material, or other export-capable field.
type Template struct {
	Algorithm     Algorithm        `json:"algorithm"`
	NameHash      HashAlgorithm    `json:"name_hash"`
	Attributes    ObjectAttributes `json:"attributes"`
	RSABits       int              `json:"rsa_bits,omitempty"`
	RSAExponent   int              `json:"rsa_exponent,omitempty"`
	Curve         string           `json:"curve,omitempty"`
	SigningScheme SignatureScheme  `json:"signing_scheme"`
}

// SigningTemplate returns the exact public template required for an algorithm.
func SigningTemplate(algorithm Algorithm) (Template, error) {
	attributes := ObjectAttributes{
		FixedTPM:            true,
		FixedParent:         true,
		SensitiveDataOrigin: true,
		UserWithAuth:        true,
		SignEncrypt:         true,
		NoDA:                true,
	}
	switch algorithm {
	case AlgorithmRSA4096:
		return Template{
			Algorithm:     algorithm,
			NameHash:      HashSHA256,
			Attributes:    attributes,
			RSABits:       4096,
			RSAExponent:   65537,
			SigningScheme: SchemeRSASSASHA256,
		}, nil
	case AlgorithmECDSAP256:
		return Template{
			Algorithm:     algorithm,
			NameHash:      HashSHA256,
			Attributes:    attributes,
			Curve:         "P-256",
			SigningScheme: SchemeECDSASHA256,
		}, nil
	case AlgorithmEd25519:
		return Template{
			Algorithm:     algorithm,
			NameHash:      HashSHA256,
			Attributes:    attributes,
			Curve:         "Ed25519",
			SigningScheme: SchemeEd25519,
		}, nil
	default:
		return Template{}, &UnsupportedCapabilityError{
			Algorithm: algorithm,
			Reason:    "unknown key algorithm",
		}
	}
}

// Public describes a persistent TPM object's public area.
type Public struct {
	Handle    Handle
	Name      []byte
	Template  Template
	PublicKey crypto.PublicKey
}

// ObjectReference pins a mutation or signing operation to an expected public
// name and template, rather than trusting a reusable numeric handle alone.
type ObjectReference struct {
	Handle   Handle
	Name     []byte
	Template Template
}

// CanonicalPublicKey returns the standard SubjectPublicKeyInfo representation
// after verifying that the public key matches the declared template.
func CanonicalPublicKey(public Public) ([]byte, error) {
	if !public.Handle.IsPersistent() {
		return nil, fmt.Errorf("TPM handle %#x is not persistent", uint32(public.Handle))
	}
	if len(public.Name) == 0 {
		return nil, errors.New("TPM public name is empty")
	}
	if err := ValidatePublicKey(public.Template, public.PublicKey); err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(public.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal TPM public key: %w", err)
	}
	return der, nil
}

// ValidatePublicKey verifies the public algorithm and parameters against a
// stored template. It never accepts a weaker parameter set.
func ValidatePublicKey(template Template, key crypto.PublicKey) error {
	expected, err := SigningTemplate(template.Algorithm)
	if err != nil {
		return err
	}
	if template != expected {
		return errors.New("TPM public template does not match the required signing template")
	}
	switch template.Algorithm {
	case AlgorithmRSA4096:
		publicKey, ok := key.(*rsa.PublicKey)
		if !ok || publicKey == nil {
			return errors.New("TPM public key is not RSA")
		}
		if publicKey.N == nil || publicKey.N.BitLen() != 4096 || publicKey.E != 65537 {
			return errors.New("TPM RSA public key is not RSA-4096 with exponent 65537")
		}
	case AlgorithmECDSAP256:
		publicKey, ok := key.(*ecdsa.PublicKey)
		if !ok || publicKey == nil {
			return errors.New("TPM public key is not ECDSA")
		}
		if _, err := publicKey.ECDH(); publicKey.Curve != elliptic.P256() || err != nil {
			return errors.New("TPM ECDSA public key is not a valid P-256 point")
		}
	case AlgorithmEd25519:
		publicKey, ok := key.(ed25519.PublicKey)
		if !ok || len(publicKey) != ed25519.PublicKeySize {
			return errors.New("TPM public key is not Ed25519")
		}
	default:
		return &UnsupportedCapabilityError{
			Algorithm: template.Algorithm,
			Reason:    "unknown key algorithm",
		}
	}
	return nil
}

// SignPurpose binds a low-level TPM operation to a reviewed manager workflow.
type SignPurpose string

const (
	SignPurposeCertificate SignPurpose = "x509-certificate"
)

// SignRequest is the complete input to a non-exportable TPM signature.
//
// Payload is a SHA-256 digest for RSA and ECDSA templates and is the message
// itself for Ed25519. Callers outside the key manager must not expose this
// low-level operation as an arbitrary signing endpoint.
type SignRequest struct {
	Object  ObjectReference
	Purpose SignPurpose
	Scheme  SignatureScheme
	Hash    crypto.Hash
	Payload []byte
}

// PreparePersistent is called exactly once after the TPM has generated and
// loaded an object, but before it is assigned its persistent handle. It exposes
// only the object's public identity so the key manager can durably record a
// recoverable creation intent. Returning an error must prevent EvictControl.
type PreparePersistent func(Public) error

// Backend is the injected, non-exporting TPM provider boundary.
//
// The interface intentionally omits TPM2_Duplicate, TPM2_Unseal, private blob
// serialization, auth-value retrieval, and every other export path.
type Backend interface {
	Supports(context.Context, Algorithm) error
	CreatePersistent(
		context.Context,
		Handle,
		Template,
		PreparePersistent,
	) (Public, error)
	ReadPublic(context.Context, Handle) (Public, error)
	Sign(context.Context, SignRequest) ([]byte, error)
	EvictPersistent(context.Context, ObjectReference) error
	Close() error
}

var (
	// ErrUnsupportedCapability identifies an algorithm or TPM operation that
	// the attached TPM cannot perform. Callers must not replace it with a
	// software implementation.
	ErrUnsupportedCapability = errors.New("TPM capability unsupported")

	// ErrHandleNotFound identifies an unoccupied persistent handle.
	ErrHandleNotFound = errors.New("TPM persistent handle not found")

	// ErrHandleOccupied identifies a persistent handle that cannot safely be
	// created or adopted.
	ErrHandleOccupied = errors.New("TPM persistent handle occupied")

	// ErrAuthorizationUnavailable means a required hierarchy or per-object
	// authorization value was not provisioned. Callers must not retry with an
	// empty authorization value.
	ErrAuthorizationUnavailable = errors.New("TPM authorization is unavailable")

	// ErrAdapterUnavailable identifies a deliberately fail-closed hardware
	// adapter that has not been implemented for the selected API version.
	ErrAdapterUnavailable = errors.New("TPM hardware adapter unavailable")
)

// UnsupportedCapabilityError carries the algorithm-specific no-fallback
// decision.
type UnsupportedCapabilityError struct {
	Algorithm Algorithm
	Reason    string
}

func (e *UnsupportedCapabilityError) Error() string {
	if e == nil {
		return ErrUnsupportedCapability.Error()
	}
	if e.Reason == "" {
		return fmt.Sprintf("%s: %s", ErrUnsupportedCapability, e.Algorithm)
	}
	return fmt.Sprintf("%s: %s: %s", ErrUnsupportedCapability, e.Algorithm, e.Reason)
}

// Is supports errors.Is(err, ErrUnsupportedCapability).
func (e *UnsupportedCapabilityError) Is(target error) bool {
	return target == ErrUnsupportedCapability
}
