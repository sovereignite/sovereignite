// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package tpm

import (
	"bytes"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"

	gotpm "github.com/google/go-tpm/tpm2"
)

func TestGoTPMPublicTemplateMapsExactSupportedParameters(t *testing.T) {
	rsaTemplate, err := SigningTemplate(AlgorithmRSA4096)
	if err != nil {
		t.Fatal(err)
	}
	rsaPublic, err := goTPMPublicTemplate(rsaTemplate)
	if err != nil {
		t.Fatal(err)
	}
	rsaParameters, err := rsaPublic.Parameters.RSADetail()
	if err != nil {
		t.Fatal(err)
	}
	if rsaPublic.Type != gotpm.TPMAlgRSA ||
		rsaPublic.NameAlg != gotpm.TPMAlgSHA256 ||
		rsaParameters.KeyBits != 4096 ||
		rsaParameters.Exponent != 65537 ||
		rsaParameters.Scheme.Scheme != gotpm.TPMAlgRSASSA {
		t.Fatalf("RSA TPM template = %#v parameters = %#v", rsaPublic, rsaParameters)
	}

	eccTemplate, err := SigningTemplate(AlgorithmECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	eccPublic, err := goTPMPublicTemplate(eccTemplate)
	if err != nil {
		t.Fatal(err)
	}
	eccParameters, err := eccPublic.Parameters.ECCDetail()
	if err != nil {
		t.Fatal(err)
	}
	if eccPublic.Type != gotpm.TPMAlgECC ||
		eccPublic.NameAlg != gotpm.TPMAlgSHA256 ||
		eccParameters.CurveID != gotpm.TPMECCNistP256 ||
		eccParameters.Scheme.Scheme != gotpm.TPMAlgECDSA {
		t.Fatalf("ECDSA TPM template = %#v parameters = %#v", eccPublic, eccParameters)
	}
}

func TestGoTPMEd25519FailsBeforeHardwareMutation(t *testing.T) {
	template, err := SigningTemplate(AlgorithmEd25519)
	if err != nil {
		t.Fatal(err)
	}
	_, err = goTPMPublicTemplate(template)
	if !errors.Is(err, ErrUnsupportedCapability) {
		t.Fatalf("goTPMPublicTemplate error = %v, want unsupported capability", err)
	}
}

func TestAuthorizationValuesAreExplicitHighEntropyAndRoleSeparated(t *testing.T) {
	valid := bytes.Repeat([]byte{0x5a}, authorizationValueBytes)
	if err := validateAuthorizationValue("test", valid); err != nil {
		t.Fatal(err)
	}
	for _, auth := range [][]byte{
		nil,
		make([]byte, authorizationValueBytes-1),
		make([]byte, authorizationValueBytes),
	} {
		if err := validateAuthorizationValue("test", auth); !errors.Is(
			err,
			ErrAuthorizationUnavailable,
		) {
			t.Fatalf("authorization validation error = %v, want unavailable", err)
		}
	}

	handle := PersistentHandleFirst + 7
	_, err := OpenGoTPM(GoTPMConfig{
		DevicePath: "/definitely/not/a/tpm",
		OwnerAuth:  valid,
		ObjectAuthByHandle: map[Handle][]byte{
			handle: bytes.Clone(valid),
		},
	})
	if !errors.Is(err, ErrAuthorizationUnavailable) {
		t.Fatalf("OpenGoTPM shared authorization error = %v, want unavailable", err)
	}
}

func TestObjectAuthorizationIsRequiredForExactHandle(t *testing.T) {
	handle := PersistentHandleFirst + 8
	configured := bytes.Repeat([]byte{0x33}, authorizationValueBytes)
	backend := &goTPMBackend{
		objectAuthByHandle: map[Handle][]byte{handle: configured},
	}
	auth, err := backend.objectAuthorizationLocked(handle)
	if err != nil {
		t.Fatal(err)
	}
	auth[0] ^= 0xff
	if configured[0] != 0x33 {
		t.Fatal("object authorization lookup returned an alias")
	}
	if _, err := backend.objectAuthorizationLocked(
		handle + 1,
	); !errors.Is(err, ErrAuthorizationUnavailable) {
		t.Fatalf("missing handle authorization error = %v, want unavailable", err)
	}
	if err := backend.evictKnownLocked(ObjectReference{
		Handle: handle + 1,
	}); !errors.Is(err, ErrAuthorizationUnavailable) {
		t.Fatalf("unconfigured eviction error = %v, want unavailable", err)
	}
}

func TestConvertGoTPMPublicRecomputesNameAndValidatesTemplate(t *testing.T) {
	template, err := SigningTemplate(AlgorithmECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	publicArea, err := goTPMPublicTemplate(template)
	if err != nil {
		t.Fatal(err)
	}
	x, y := elliptic.P256().ScalarBaseMult([]byte{7})
	publicArea.Unique = gotpm.NewTPMUPublicID(
		gotpm.TPMAlgECC,
		&gotpm.TPMSECCPoint{
			X: gotpm.TPM2BECCParameter{Buffer: x.FillBytes(make([]byte, 32))},
			Y: gotpm.TPM2BECCParameter{Buffer: y.FillBytes(make([]byte, 32))},
		},
	)
	name, err := gotpm.ObjectName(&publicArea)
	if err != nil {
		t.Fatal(err)
	}
	converted, err := convertGoTPMPublic(
		PersistentHandleFirst,
		name.Buffer,
		&publicArea,
	)
	if err != nil {
		t.Fatal(err)
	}
	if converted.Template != template || converted.Handle != PersistentHandleFirst {
		t.Fatalf("converted public = %#v", converted)
	}
	if _, err := convertGoTPMPublic(
		PersistentHandleFirst,
		[]byte("tampered-name"),
		&publicArea,
	); err == nil {
		t.Fatal("convertGoTPMPublic accepted a mismatched TPM Name")
	}
	publicArea.ObjectAttributes.FixedTPM = false
	mutatedName, err := gotpm.ObjectName(&publicArea)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := convertGoTPMPublic(
		PersistentHandleFirst,
		mutatedName.Buffer,
		&publicArea,
	); err == nil {
		t.Fatal("convertGoTPMPublic accepted a mutable public template")
	}
}

func TestSignatureBytesUsesCryptoSignerEncodings(t *testing.T) {
	rsaTemplate, err := SigningTemplate(AlgorithmRSA4096)
	if err != nil {
		t.Fatal(err)
	}
	rsaBytes := make([]byte, 512)
	rsaBytes[0] = 1
	rsaSignature := gotpm.TPMTSignature{
		SigAlg: gotpm.TPMAlgRSASSA,
		Signature: gotpm.NewTPMUSignature(
			gotpm.TPMAlgRSASSA,
			&gotpm.TPMSSignatureRSA{
				Hash: gotpm.TPMAlgSHA256,
				Sig:  gotpm.TPM2BPublicKeyRSA{Buffer: rsaBytes},
			},
		),
	}
	encodedRSA, err := signatureBytes(rsaTemplate, rsaSignature)
	if err != nil {
		t.Fatal(err)
	}
	if len(encodedRSA) != 512 {
		t.Fatalf("RSA signature length = %d, want 512", len(encodedRSA))
	}

	eccTemplate, err := SigningTemplate(AlgorithmECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	eccSignature := gotpm.TPMTSignature{
		SigAlg: gotpm.TPMAlgECDSA,
		Signature: gotpm.NewTPMUSignature(
			gotpm.TPMAlgECDSA,
			&gotpm.TPMSSignatureECC{
				Hash:       gotpm.TPMAlgSHA256,
				SignatureR: gotpm.TPM2BECCParameter{Buffer: []byte{1}},
				SignatureS: gotpm.TPM2BECCParameter{Buffer: []byte{2}},
			},
		),
	}
	encodedECC, err := signatureBytes(eccTemplate, eccSignature)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		R *big.Int
		S *big.Int
	}
	if rest, err := asn1.Unmarshal(encodedECC, &decoded); err != nil || len(rest) != 0 {
		t.Fatalf("decode ECDSA signature: rest=%x error=%v", rest, err)
	}
	if decoded.R.Cmp(big.NewInt(1)) != 0 || decoded.S.Cmp(big.NewInt(2)) != 0 {
		t.Fatalf("ECDSA signature = (%s, %s), want (1, 2)", decoded.R, decoded.S)
	}
}
