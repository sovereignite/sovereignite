// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package tpm

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"math/big"
	"reflect"
	"testing"
)

func TestSigningTemplateUsesFixedNonExportableSigningAttributes(t *testing.T) {
	for _, algorithm := range []Algorithm{
		AlgorithmRSA4096,
		AlgorithmECDSAP256,
		AlgorithmEd25519,
	} {
		t.Run(string(algorithm), func(t *testing.T) {
			template, err := SigningTemplate(algorithm)
			if err != nil {
				t.Fatal(err)
			}
			if !template.Attributes.FixedTPM ||
				!template.Attributes.FixedParent ||
				!template.Attributes.SensitiveDataOrigin ||
				!template.Attributes.UserWithAuth ||
				!template.Attributes.SignEncrypt ||
				!template.Attributes.NoDA {
				t.Fatalf("template attributes = %#v, want fixed TPM-originated signer", template.Attributes)
			}
			if template.NameHash != HashSHA256 {
				t.Fatalf("name hash = %q, want SHA-256", template.NameHash)
			}
		})
	}
}

func TestCanonicalPublicKeyValidatesExactAlgorithmParameters(t *testing.T) {
	rsaModulus := new(big.Int).Lsh(big.NewInt(1), 4095)
	rsaModulus.Add(rsaModulus, big.NewInt(123))
	rsaTemplate, err := SigningTemplate(AlgorithmRSA4096)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaTemplate, err := SigningTemplate(AlgorithmECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	ed25519Template, err := SigningTemplate(AlgorithmEd25519)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaPrivate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ed25519Public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	testCases := []struct {
		name     string
		template Template
		key      any
	}{
		{
			name:     "RSA-4096",
			template: rsaTemplate,
			key:      &rsa.PublicKey{N: rsaModulus, E: 65537},
		},
		{
			name:     "ECDSA-P256",
			template: ecdsaTemplate,
			key:      &ecdsaPrivate.PublicKey,
		},
		{
			name:     "Ed25519",
			template: ed25519Template,
			key:      ed25519Public,
		},
	}
	for index, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			der, err := CanonicalPublicKey(Public{
				Handle:    PersistentHandleFirst + Handle(index),
				Name:      []byte("public-name"),
				Template:  testCase.template,
				PublicKey: testCase.key,
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(der) == 0 {
				t.Fatal("canonical public key is empty")
			}
		})
	}
}

func TestValidatePublicKeyRejectsDowngradeAndTemplateMutation(t *testing.T) {
	template, err := SigningTemplate(AlgorithmRSA4096)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePublicKey(
		template,
		&rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 2047), E: 65537},
	); err == nil {
		t.Fatal("ValidatePublicKey accepted RSA-2048 for RSA-4096 template")
	}
	template.Attributes.FixedTPM = false
	if err := ValidatePublicKey(template, &rsa.PublicKey{}); err == nil {
		t.Fatal("ValidatePublicKey accepted a mutable/exportable template")
	}
}

func TestUnknownAlgorithmIsExplicitlyUnsupported(t *testing.T) {
	_, err := SigningTemplate(Algorithm("rsa-2048"))
	if !errors.Is(err, ErrUnsupportedCapability) {
		t.Fatalf("SigningTemplate error = %v, want unsupported capability", err)
	}
}

func TestOpenGoTPMRequiresExplicitDevice(t *testing.T) {
	if _, err := OpenGoTPM(GoTPMConfig{}); err == nil {
		t.Fatal("OpenGoTPM accepted an empty device path")
	}
}

func TestPersistentHandleRangeIsOwnerAuthorizedOnly(t *testing.T) {
	for _, handle := range []Handle{
		PersistentHandleFirst,
		PersistentHandleLast,
	} {
		if !handle.IsPersistent() {
			t.Fatalf("owner-persistent handle %#x was rejected", uint32(handle))
		}
	}
	for _, handle := range []Handle{
		PersistentHandleFirst - 1,
		PersistentHandleLast + 1,
		0x81ffffff,
	} {
		if handle.IsPersistent() {
			t.Fatalf("non-owner-persistent handle %#x was accepted", uint32(handle))
		}
	}
}

func TestBackendBoundaryHasNoPrivateExportMethod(t *testing.T) {
	backendType := reflect.TypeOf((*Backend)(nil)).Elem()
	want := []string{
		"Close",
		"CreatePersistent",
		"EvictPersistent",
		"ReadPublic",
		"Sign",
		"Supports",
	}
	got := make([]string, 0, backendType.NumMethod())
	for index := 0; index < backendType.NumMethod(); index++ {
		got = append(got, backendType.Method(index).Name)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Backend methods = %v, want exactly %v", got, want)
	}
}

func TestSigningTemplateCoversAllRequestedAlgorithms(t *testing.T) {
	for _, testCase := range []struct {
		algorithm Algorithm
		wantBits  int
		wantCurve string
		wantHash  HashAlgorithm
	}{
		{AlgorithmRSA4096, 4096, "", HashSHA256},
		{AlgorithmECDSAP256, 0, "P-256", HashSHA256},
		{AlgorithmEd25519, 0, "Ed25519", HashSHA256},
	} {
		t.Run(string(testCase.algorithm), func(t *testing.T) {
			template, err := SigningTemplate(testCase.algorithm)
			if err != nil {
				t.Fatal(err)
			}
			if template.RSABits != testCase.wantBits {
				t.Fatalf("RSA bits = %d, want %d", template.RSABits, testCase.wantBits)
			}
			if template.Curve != testCase.wantCurve {
				t.Fatalf("curve = %q, want %q", template.Curve, testCase.wantCurve)
			}
			if template.NameHash != testCase.wantHash {
				t.Fatalf("name hash = %q, want %q", template.NameHash, testCase.wantHash)
			}
		})
	}
}

func TestSigningTemplateRejectsUnknownAlgorithm(t *testing.T) {
	_, err := SigningTemplate(Algorithm("unknown"))
	if !errors.Is(err, ErrUnsupportedCapability) {
		t.Fatalf("SigningTemplate error = %v, want unsupported capability", err)
	}
}

func TestValidatePublicKeyAcceptsAllRequestedAlgorithms(t *testing.T) {
	rsaModulus := new(big.Int).Lsh(big.NewInt(1), 4095)
	rsaModulus.Add(rsaModulus, big.NewInt(123))
	rsaKey := &rsa.PublicKey{N: rsaModulus, E: 65537}
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ed25519Pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	for _, testCase := range []struct {
		algorithm Algorithm
		key       any
	}{
		{AlgorithmRSA4096, rsaKey},
		{AlgorithmECDSAP256, &ecdsaKey.PublicKey},
		{AlgorithmEd25519, ed25519Pub},
	} {
		t.Run(string(testCase.algorithm), func(t *testing.T) {
			template, err := SigningTemplate(testCase.algorithm)
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidatePublicKey(template, testCase.key); err != nil {
				t.Fatalf("ValidatePublicKey error = %v", err)
			}
		})
	}
}

func TestValidatePublicKeyRejectsMismatchedAlgorithm(t *testing.T) {
	rsaTemplate, err := SigningTemplate(AlgorithmRSA4096)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePublicKey(rsaTemplate, &ecdsaKey.PublicKey); err == nil {
		t.Fatal("ValidatePublicKey accepted ECDSA key for RSA template")
	}
}

func TestHandlePersistentRange(t *testing.T) {
	valid := []Handle{PersistentHandleFirst, PersistentHandleLast}
	for _, handle := range valid {
		if !handle.IsPersistent() {
			t.Fatalf("handle %#x should be persistent", uint32(handle))
		}
	}
	invalid := []Handle{PersistentHandleFirst - 1, PersistentHandleLast + 1, 0}
	for _, handle := range invalid {
		if handle.IsPersistent() {
			t.Fatalf("handle %#x should not be persistent", uint32(handle))
		}
	}
}

func TestUnsupportedCapabilityErrorWrapsCorrectly(t *testing.T) {
	err := &UnsupportedCapabilityError{
		Algorithm: Algorithm("unknown"),
		Reason:    "test reason",
	}
	if !errors.Is(err, ErrUnsupportedCapability) {
		t.Fatal("UnsupportedCapabilityError does not wrap ErrUnsupportedCapability")
	}
	if err.Error() != "TPM capability unsupported: unknown: test reason" {
		t.Fatalf("error message = %q", err.Error())
	}
	var nilErr *UnsupportedCapabilityError
	if nilErr.Error() != ErrUnsupportedCapability.Error() {
		t.Fatalf("nil error message = %q", nilErr.Error())
	}
}

func TestSigningTemplateNonExportableAttributes(t *testing.T) {
	for _, algorithm := range []Algorithm{
		AlgorithmRSA4096,
		AlgorithmECDSAP256,
		AlgorithmEd25519,
	} {
		t.Run(string(algorithm), func(t *testing.T) {
			template, err := SigningTemplate(algorithm)
			if err != nil {
				t.Fatal(err)
			}
			if !template.Attributes.FixedTPM {
				t.Fatal("FixedTPM is false")
			}
			if !template.Attributes.FixedParent {
				t.Fatal("FixedParent is false")
			}
			if !template.Attributes.SensitiveDataOrigin {
				t.Fatal("SensitiveDataOrigin is false")
			}
			if !template.Attributes.UserWithAuth {
				t.Fatal("UserWithAuth is false")
			}
			if !template.Attributes.SignEncrypt {
				t.Fatal("SignEncrypt is false")
			}
			if !template.Attributes.NoDA {
				t.Fatal("NoDA is false")
			}
		})
	}
}

func TestCanonicalPublicKeyRejectsNonPersistentHandle(t *testing.T) {
	_, err := CanonicalPublicKey(Public{
		Handle:    Handle(0x100),
		Name:      []byte("test"),
		Template:  Template{Algorithm: AlgorithmRSA4096},
		PublicKey: &rsa.PublicKey{},
	})
	if err == nil {
		t.Fatal("CanonicalPublicKey accepted non-persistent handle")
	}
}

func TestCanonicalPublicKeyRejectsEmptyName(t *testing.T) {
	template, err := SigningTemplate(AlgorithmEd25519)
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = CanonicalPublicKey(Public{
		Handle:    PersistentHandleFirst,
		Name:      nil,
		Template:  template,
		PublicKey: pub,
	})
	if err == nil {
		t.Fatal("CanonicalPublicKey accepted empty name")
	}
}
