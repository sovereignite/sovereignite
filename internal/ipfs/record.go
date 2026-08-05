// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package ipfs

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/ipfs/go-cid"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
)

const (
	// SignedRecordBoundaryV1 identifies the reviewed, pre-signed publication
	// boundary. It is deliberately not represented as stock Kubo private-key
	// configuration or claimed to be Kubo's IPNS wire serialization. A future
	// authorized full-Kubo adapter must convert or inject it coherently.
	SignedRecordBoundaryV1 = "sovereignite-ipns-boundary-v1"

	recordSignatureDomain = "github.com/sovereignite/sovereignite/ipns-record/v1\x00"
	recordEnvelopeDomain  = "github.com/sovereignite/sovereignite/ipns-envelope/v1\x00"
)

// SignedRecord binds one monotonic sequence to one immutable /ipfs root.
// Signature contains public signature bytes only.
type SignedRecord struct {
	Format     string        `json:"format"`
	Name       string        `json:"name"`
	Value      string        `json:"value"`
	Sequence   uint64        `json:"sequence"`
	IssuedAt   time.Time     `json:"issued_at"`
	ValidUntil time.Time     `json:"valid_until"`
	TTL        time.Duration `json:"ttl_nanoseconds"`
	Signature  []byte        `json:"signature"`
}

// Clone returns a copy safe for persistence or an injected node to retain.
func (r SignedRecord) Clone() SignedRecord {
	r.Signature = slices.Clone(r.Signature)
	return r
}

// RootCID parses and canonically validates the /ipfs value.
func (r SignedRecord) RootCID() (cid.Cid, error) {
	const prefix = "/ipfs/"
	if !strings.HasPrefix(r.Value, prefix) {
		return cid.Undef, errors.New("signed record value is not an /ipfs path")
	}
	encoded := strings.TrimPrefix(r.Value, prefix)
	if encoded == "" || strings.Contains(encoded, "/") {
		return cid.Undef, errors.New("signed record value is not a root CID")
	}
	root, err := cid.Decode(encoded)
	if err != nil {
		return cid.Undef, fmt.Errorf("decode signed record root CID: %w", err)
	}
	if !root.Defined() || root.Version() != 1 || root.String() != encoded {
		return cid.Undef, errors.New(
			"signed record root is not a canonical CIDv1",
		)
	}
	return root, nil
}

// MarshalBinary returns a deterministic audit/persistence envelope for this
// boundary. It is not advertised as Kubo's IPNS protobuf wire representation.
func (r SignedRecord) MarshalBinary() ([]byte, error) {
	unsigned, err := r.unsignedPayload()
	if err != nil {
		return nil, err
	}
	if len(r.Signature) == 0 {
		return nil, errors.New("signed record signature is required")
	}
	envelope := append([]byte(recordEnvelopeDomain), unsigned...)
	envelope = appendLengthPrefixed(envelope, r.Signature)
	return envelope, nil
}

// Digest returns a stable digest of the complete public signed envelope.
func (r SignedRecord) Digest() (string, error) {
	encoded, err := r.MarshalBinary()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

// RecordValidation supplies the expected binding and anti-rollback high-water
// mark for a received record.
type RecordValidation struct {
	ExpectedName     string
	ExpectedRoot     cid.Cid
	PreviousSequence uint64
	PreviousIssuedAt time.Time
	Now              time.Time
	Policy           RecordPolicy
	PublicKey        libp2pcrypto.PubKey
}

// CreateSignedRecord creates a fresh, whole-second record and signs only the
// domain-separated canonical payload through the TPM adapter.
func CreateSignedRecord(
	ctx context.Context,
	signer *TPMIPNSSigner,
	root cid.Cid,
	sequence uint64,
	now time.Time,
	policy RecordPolicy,
) (SignedRecord, error) {
	if isNil(ctx) {
		return SignedRecord{}, errors.New("record signing context is required")
	}
	if signer == nil {
		return SignedRecord{}, errors.New("TPM IPNS signer is required")
	}
	if !root.Defined() || root.Version() != 1 {
		return SignedRecord{}, errors.New("record root must be a CIDv1")
	}
	if sequence == 0 {
		return SignedRecord{}, errors.New("record sequence must be positive")
	}
	if now.IsZero() {
		return SignedRecord{}, errors.New("record issue time is required")
	}
	if err := policy.Validate(); err != nil {
		return SignedRecord{}, err
	}
	issuedAt := now.UTC().Truncate(time.Second)
	record := SignedRecord{
		Format:     SignedRecordBoundaryV1,
		Name:       signer.Name(),
		Value:      "/ipfs/" + root.String(),
		Sequence:   sequence,
		IssuedAt:   issuedAt,
		ValidUntil: issuedAt.Add(policy.Validity),
		TTL:        policy.Validity,
	}
	payload, err := record.unsignedPayload()
	if err != nil {
		return SignedRecord{}, err
	}
	signature, err := signer.SignContext(ctx, payload)
	if err != nil {
		return SignedRecord{}, err
	}
	record.Signature = signature
	if err := ValidateSignedRecord(record, RecordValidation{
		ExpectedName: signer.Name(),
		ExpectedRoot: root,
		Now:          issuedAt,
		Policy:       policy,
		PublicKey:    signer.GetPublic(),
	}); err != nil {
		return SignedRecord{}, fmt.Errorf(
			"validate newly signed publication record: %w",
			err,
		)
	}
	return record, nil
}

// ValidateSignedRecord verifies canonical identity/root binding, signature,
// expiry, maximum lifetime, maximum staleness, and strict sequence rollback
// protection.
func ValidateSignedRecord(
	record SignedRecord,
	validation RecordValidation,
) error {
	if err := validation.Policy.Validate(); err != nil {
		return err
	}
	if validation.Now.IsZero() {
		return errors.New("record validation time is required")
	}
	if isNil(validation.PublicKey) {
		return errors.New("record validation public key is required")
	}
	if validation.ExpectedName == "" {
		return errors.New("expected IPNS name is required")
	}
	if !validation.ExpectedRoot.Defined() {
		return errors.New("expected IPFS root CID is required")
	}
	if err := verifyRecordBindingAndSignature(
		record,
		validation.ExpectedName,
		validation.ExpectedRoot,
		validation.PublicKey,
	); err != nil {
		return err
	}
	if err := validateRecordLifetime(record, validation.Policy); err != nil {
		return err
	}
	if record.Sequence <= validation.PreviousSequence {
		return fmt.Errorf(
			"IPNS sequence %d does not advance high-water mark %d",
			record.Sequence,
			validation.PreviousSequence,
		)
	}
	if !validation.PreviousIssuedAt.IsZero() &&
		record.IssuedAt.Before(validation.PreviousIssuedAt) {
		return errors.New("IPNS record issue time rolled back")
	}
	now := validation.Now.UTC()
	if record.IssuedAt.After(now.Add(validation.Policy.ClockSkew)) {
		return errors.New("IPNS record issue time is too far in the future")
	}
	if now.After(record.IssuedAt) &&
		now.Sub(record.IssuedAt) > validation.Policy.MaxStaleness {
		return errors.New("IPNS record exceeds maximum staleness")
	}
	if !record.ValidUntil.After(now) {
		return errors.New("IPNS record is expired")
	}
	return nil
}

func verifyRecordBindingAndSignature(
	record SignedRecord,
	expectedName string,
	expectedRoot cid.Cid,
	publicKey libp2pcrypto.PubKey,
) error {
	if isNil(publicKey) {
		return errors.New("record public key is required")
	}
	_, derivedName, _, err := canonicalIdentityForPublicKey(publicKey)
	if err != nil {
		return err
	}
	if record.Name != expectedName || record.Name != derivedName {
		return errors.New("IPNS record is bound to the wrong name")
	}
	root, err := record.RootCID()
	if err != nil {
		return err
	}
	if !expectedRoot.Defined() || !root.Equals(expectedRoot) {
		return errors.New("IPNS record is bound to the wrong root CID")
	}
	payload, err := record.unsignedPayload()
	if err != nil {
		return err
	}
	if len(record.Signature) == 0 {
		return errors.New("IPNS record signature is required")
	}
	valid, err := publicKey.Verify(payload, record.Signature)
	if err != nil {
		return fmt.Errorf("verify IPNS record signature: %w", err)
	}
	if !valid {
		return errors.New("IPNS record signature is invalid")
	}
	return nil
}

func (r SignedRecord) unsignedPayload() ([]byte, error) {
	if r.Format != SignedRecordBoundaryV1 {
		return nil, errors.New("signed record boundary format is unsupported")
	}
	if err := validateCanonicalIPNSName(r.Name); err != nil {
		return nil, err
	}
	if _, err := r.RootCID(); err != nil {
		return nil, err
	}
	if r.Sequence == 0 {
		return nil, errors.New("signed record sequence must be positive")
	}
	if !canonicalWholeSecond(r.IssuedAt) ||
		!canonicalWholeSecond(r.ValidUntil) {
		return nil, errors.New(
			"signed record times must be canonical whole UTC seconds",
		)
	}
	if !r.ValidUntil.After(r.IssuedAt) {
		return nil, errors.New(
			"signed record expiration must follow its issue time",
		)
	}
	validity := r.ValidUntil.Sub(r.IssuedAt)
	if r.TTL <= 0 || r.TTL > validity || r.TTL%time.Second != 0 {
		return nil, errors.New("signed record TTL is invalid")
	}
	payload := []byte(recordSignatureDomain)
	payload = appendLengthPrefixed(payload, []byte(r.Format))
	payload = appendLengthPrefixed(payload, []byte(r.Name))
	payload = appendLengthPrefixed(payload, []byte(r.Value))
	payload = appendUint64(payload, r.Sequence)
	payload = appendInt64(payload, r.IssuedAt.Unix())
	payload = appendInt64(payload, r.ValidUntil.Unix())
	payload = appendInt64(payload, int64(r.TTL))
	return payload, nil
}

func validateRecordLifetime(
	record SignedRecord,
	policy RecordPolicy,
) error {
	validity := record.ValidUntil.Sub(record.IssuedAt)
	if validity > policy.MaxValidity {
		return errors.New("IPNS record validity exceeds its maximum")
	}
	return nil
}

func canonicalWholeSecond(value time.Time) bool {
	return !value.IsZero() &&
		value.Location() == time.UTC &&
		value.Nanosecond() == 0
}

func appendLengthPrefixed(destination, value []byte) []byte {
	destination = appendUint64(destination, uint64(len(value)))
	return append(destination, value...)
}

func appendUint64(destination []byte, value uint64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return append(destination, encoded[:]...)
}

func appendInt64(destination []byte, value int64) []byte {
	return appendUint64(destination, uint64(value))
}
