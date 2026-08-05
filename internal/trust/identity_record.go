// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package trust

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

const (
	firstPersistentHandle uint32 = 0x81000000
	lastPersistentHandle  uint32 = 0x81ffffff
)

// IdentityPhase is the lifecycle state of a device identity record.
type IdentityPhase string

const (
	IdentityPhasePending IdentityPhase = "pending"
	IdentityPhaseActive  IdentityPhase = "active"
	IdentityPhaseRevoked IdentityPhase = "revoked"
)

// IdentityRecord is the versioned internal Trust record that maps from
// libp2p peer.AddrInfo to a structured device identity. It never contains
// private keys, CRDs, or exportable key material.
type IdentityRecord struct {
	PeerID             string              `json:"peer_id"`
	Addrs              []string            `json:"addrs"`
	Keys               []IdentityRecordKey `json:"keys"`
	Handle             uint32              `json:"handle"`
	Phase              IdentityPhase       `json:"phase"`
	PeerRecordSequence uint64              `json:"peer_record_sequence"`
	SPIFFEID           string              `json:"spiffe_id"`
	X509SVID           *X509SVID           `json:"x509_svid,omitempty"`
	Conditions         []IdentityCondition `json:"conditions"`
	Generation         uint64              `json:"generation"`
	ObservedGeneration uint64              `json:"observed_generation"`
}

// IdentityRecordKey contains only public key material and a reference to the
// TPM persistent handle. It never contains private key bytes.
type IdentityRecordKey struct {
	Type      string `json:"type"`
	RawBase64 string `json:"raw_base64"`
	TPMHandle string `json:"tpm_handle"`
}

// X509SVID contains public X.509 certificate chain material.
type X509SVID struct {
	CertificateChain [][]byte `json:"certificate_chain"`
	Expiry           time.Time `json:"expiry"`
}

// IdentityCondition records one observed property of the identity.
type IdentityCondition struct {
	Type               string    `json:"type"`
	Status             string    `json:"status"`
	Reason             string    `json:"reason"`
	Message            string    `json:"message"`
	LastTransitionTime time.Time `json:"last_transition_time"`
}

// IdentityEnvelope wraps a peer.PeerRecord with its canonical address info.
type IdentityEnvelope struct {
	AddrInfo  peer.AddrInfo `json:"addr_info"`
	Sequence  uint64        `json:"sequence"`
	Addresses []string      `json:"addresses"`
}

// MapAddrInfoToIdentityRecord maps a libp2p peer.AddrInfo to an internal
// IdentityRecord. It never copies private keys.
func MapAddrInfoToIdentityRecord(
	addrInfo peer.AddrInfo,
	publicKey libp2pcrypto.PubKey,
	handle uint32,
	spiffeID string,
) (IdentityRecord, error) {
	if err := validateTPMHandle(handle); err != nil {
		return IdentityRecord{}, fmt.Errorf("invalid TPM handle: %w", err)
	}
	if publicKey == nil {
		return IdentityRecord{}, errors.New("public key is required")
	}
	peerID := addrInfo.ID.String()
	if peerID == "" {
		return IdentityRecord{}, errors.New("peer ID is required")
	}
	if _, err := peer.Decode(peerID); err != nil {
		return IdentityRecord{}, fmt.Errorf("decode peer ID: %w", err)
	}
	if spiffeID == "" {
		return IdentityRecord{}, errors.New("SPIFFE ID is required")
	}
	if _, err := ParseDeviceSPIFFEID(spiffeID); err != nil {
		return IdentityRecord{}, fmt.Errorf("SPIFFE ID: %w", err)
	}
	keyType, rawBytes, err := marshalPublicKey(publicKey)
	if err != nil {
		return IdentityRecord{}, fmt.Errorf("marshal public key: %w", err)
	}
	addrs := make([]string, 0, len(addrInfo.Addrs))
	for _, addr := range addrInfo.Addrs {
		addrs = append(addrs, addr.String())
	}
	return IdentityRecord{
		PeerID: peerID,
		Addrs:  addrs,
		Keys: []IdentityRecordKey{
			{
				Type:      keyType,
				RawBase64: base64.StdEncoding.EncodeToString(rawBytes),
				TPMHandle: formatTPMHandle(handle),
			},
		},
		Handle:   handle,
		Phase:    IdentityPhasePending,
		SPIFFEID: spiffeID,
	}, nil
}

// MapPeerRecordToIdentityRecord applies a signed peer.PeerRecord envelope to an
// existing identity record. The envelope sequence must be greater than or equal
// to the record's current peer record sequence.
func MapPeerRecordToIdentityRecord(
	record IdentityRecord,
	envelope IdentityEnvelope,
) (IdentityRecord, error) {
	if envelope.Sequence < record.PeerRecordSequence {
		return IdentityRecord{}, ErrStalePeerRecordEnvelope
	}
	result := record
	result.PeerRecordSequence = envelope.Sequence
	if len(envelope.Addresses) > 0 {
		result.Addrs = slices.Clone(envelope.Addresses)
	} else if envelope.AddrInfo.Addrs != nil {
		addrs := make([]string, 0, len(envelope.AddrInfo.Addrs))
		for _, addr := range envelope.AddrInfo.Addrs {
			addrs = append(addrs, addr.String())
		}
		result.Addrs = addrs
	}
	return result, nil
}

// ValidateIdentityRecord checks internal consistency of the identity record
// without external state.
func ValidateIdentityRecord(record IdentityRecord, localPeerID string) error {
	if record.PeerID == "" {
		return errors.New("peer ID is required")
	}
	if _, err := peer.Decode(record.PeerID); err != nil {
		return fmt.Errorf("decode peer ID: %w", err)
	}
	if record.PeerID != localPeerID {
		return ErrMismatchedPeerID
	}
	if len(record.Addrs) == 0 {
		return errors.New("at least one address is required")
	}
	for i, addr := range record.Addrs {
		if _, err := multiaddr.NewMultiaddr(addr); err != nil {
			return fmt.Errorf("address %d: invalid multiaddr: %w", i, err)
		}
	}
	if len(record.Keys) == 0 {
		return errors.New("at least one public key is required")
	}
	for i, key := range record.Keys {
		if key.Type == "" {
			return fmt.Errorf("key %d: type is required", i)
		}
		if key.RawBase64 == "" {
			return fmt.Errorf("key %d: raw bytes are required", i)
		}
		rawBytes, err := base64.StdEncoding.DecodeString(key.RawBase64)
		if err != nil {
			return fmt.Errorf("key %d: decode base64: %w", i, err)
		}
		if len(rawBytes) == 0 {
			return fmt.Errorf("key %d: raw bytes must be non-empty", i)
		}
		if key.TPMHandle == "" {
			return fmt.Errorf("key %d: TPM handle is required", i)
		}
		if err := validatePublicKeyType(key.Type); err != nil {
			return fmt.Errorf("key %d: %w", i, err)
		}
	}
	if record.Handle == 0 {
		return errors.New("TPM handle is required")
	}
	if record.Phase != IdentityPhasePending &&
		record.Phase != IdentityPhaseActive &&
		record.Phase != IdentityPhaseRevoked {
		return errors.New("identity phase is invalid")
	}
	if record.SPIFFEID == "" {
		return errors.New("SPIFFE ID is required")
	}
	if _, err := ParseDeviceSPIFFEID(record.SPIFFEID); err != nil {
		return fmt.Errorf("SPIFFE ID: %w", err)
	}
	if record.Generation == 0 && record.Phase != IdentityPhasePending {
		return errors.New("generation must be positive for non-pending identity")
	}
	if record.Generation > 0 && record.ObservedGeneration > record.Generation {
		return ErrStaleGeneration
	}
	return nil
}

// ValidatePublicKeyPeerIDConsistency verifies that a libp2p public key derives
// the expected peer ID.
func ValidatePublicKeyPeerIDConsistency(
	publicKey libp2pcrypto.PubKey,
	expectedPeerID string,
) error {
	derivedPeerID, err := peer.IDFromPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("derive peer ID from public key: %w", err)
	}
	if derivedPeerID.String() != expectedPeerID {
		return ErrMismatchedPublicKey
	}
	return nil
}

// ValidateHandleOwnership verifies that the given handle is a locally-known
// TPM persistent handle, not a foreign or unknown handle.
func ValidateHandleOwnership(record IdentityRecord, localHandle uint32) error {
	if record.Handle != localHandle {
		return ErrUnknownHandle
	}
	for _, key := range record.Keys {
		expected := formatTPMHandle(localHandle)
		if key.TPMHandle != expected {
			return ErrUnknownHandle
		}
	}
	return nil
}

// ValidateX509SVID maps and validates an X.509 certificate chain into the
// identity record's SVID field. It rejects private-key PEM blocks.
func ValidateX509SVID(record IdentityRecord, certChain [][]byte) (IdentityRecord, error) {
	if len(certChain) == 0 {
		return record, nil
	}
	expiry := time.Time{}
	for i, der := range certChain {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return IdentityRecord{}, fmt.Errorf("SVID certificate %d: %w", i, err)
		}
		if i == 0 && !cert.NotAfter.IsZero() {
			expiry = cert.NotAfter.UTC()
		}
	}
	result := record
	result.X509SVID = &X509SVID{
		CertificateChain: cloneByteSlices(certChain),
		Expiry:           expiry,
	}
	return result, nil
}

// TransitionIdentityPhase validates and applies a phase transition. Only
// authorized transitions are permitted: pending→active, active→revoked.
func TransitionIdentityPhase(
	record IdentityRecord,
	targetPhase IdentityPhase,
	now time.Time,
) (IdentityRecord, error) {
	if now.IsZero() {
		return IdentityRecord{}, errors.New("transition time is required")
	}
	switch record.Phase {
	case IdentityPhasePending:
		if targetPhase != IdentityPhaseActive {
			return IdentityRecord{}, ErrInvalidPhaseTransition
		}
	case IdentityPhaseActive:
		if targetPhase != IdentityPhaseRevoked {
			return IdentityRecord{}, ErrInvalidPhaseTransition
		}
	case IdentityPhaseRevoked:
		return IdentityRecord{}, ErrIdentityAlreadyRevoked
	default:
		return IdentityRecord{}, errors.New("source identity phase is invalid")
	}
	result := record
	result.Phase = targetPhase
	result.Generation++
	result.Conditions = append(result.Conditions, IdentityCondition{
		Type:               "PhaseTransition",
		Status:             "True",
		Reason:             fmt.Sprintf("%s→%s", record.Phase, targetPhase),
		Message:            fmt.Sprintf("Identity phase transitioned from %s to %s", record.Phase, targetPhase),
		LastTransitionTime: now.UTC(),
	})
	return result, nil
}

// IdentityRecordToProto converts an internal IdentityRecord to the proto
// DeviceIdentity message.
func IdentityRecordToProto(record IdentityRecord) map[string]any {
	keys := make([]map[string]any, 0, len(record.Keys))
	for _, key := range record.Keys {
		keys = append(keys, map[string]any{
			"type":        key.Type,
			"raw_base64":  key.RawBase64,
			"tpm_handle":  key.TPMHandle,
		})
	}
	phase := "IDENTITY_PHASE_UNSPECIFIED"
	switch record.Phase {
	case IdentityPhasePending:
		phase = "IDENTITY_PHASE_PENDING"
	case IdentityPhaseActive:
		phase = "IDENTITY_PHASE_ACTIVE"
	case IdentityPhaseRevoked:
		phase = "IDENTITY_PHASE_REVOKED"
	}
	result := map[string]any{
		"peer_id":               record.PeerID,
		"multiaddrs":            record.Addrs,
		"public_keys":           keys,
		"phase":                 phase,
		"peer_record_sequence":  record.PeerRecordSequence,
		"spiffe_id":             record.SPIFFEID,
		"observed_generation":   record.ObservedGeneration,
	}
	if record.X509SVID != nil {
		certs := make([]string, 0, len(record.X509SVID.CertificateChain))
		for _, der := range record.X509SVID.CertificateChain {
			certs = append(certs, base64.StdEncoding.EncodeToString(der))
		}
		result["x509_svid"] = map[string]any{
			"certificate_chain": certs,
			"expires_at":        record.X509SVID.Expiry.Format(time.RFC3339),
		}
	}
	if len(record.Conditions) > 0 {
		conditions := make([]map[string]any, 0, len(record.Conditions))
		for _, c := range record.Conditions {
			conditions = append(conditions, map[string]any{
				"type":                  c.Type,
				"status":                c.Status,
				"reason":                c.Reason,
				"message":               c.Message,
				"last_transition_time":  c.LastTransitionTime.Format(time.RFC3339),
			})
		}
		result["conditions"] = conditions
	}
	return result
}

func marshalPublicKey(key libp2pcrypto.PubKey) (string, []byte, error) {
	rawBytes, err := libp2pcrypto.MarshalPublicKey(key)
	if err != nil {
		return "", nil, err
	}
	keyType := classifyKeyType(key)
	return keyType, rawBytes, nil
}

func classifyKeyType(key libp2pcrypto.PubKey) string {
	typeName := fmt.Sprintf("%T", key)
	switch {
	case strings.Contains(typeName, "Ed25519PublicKey"):
		return "Ed25519"
	case strings.Contains(typeName, "ECDSAPublicKey"):
		return "ECDSA"
	case strings.Contains(typeName, "RSAPublicKey"):
		return "RSA"
	case strings.Contains(typeName, "Secp256k1PublicKey"):
		return "Secp256k1"
	default:
		return "Unknown"
	}
}

func validatePublicKeyType(keyType string) error {
	switch keyType {
	case "Ed25519", "ECDSA", "RSA", "Secp256k1":
		return nil
	default:
		return fmt.Errorf("unsupported public key type: %q", keyType)
	}
}

func formatTPMHandle(handle uint32) string {
	return fmt.Sprintf("0x%08X", handle)
}

// ValidateSPIFFEDerivation proves the SPIFFE ID is correctly derived from the
// trust domain and peer ID in the identity record.
func ValidateSPIFFEDerivation(record IdentityRecord) error {
	if record.SPIFFEID == "" {
		return errors.New("SPIFFE ID is required")
	}
	if record.PeerID == "" {
		return errors.New("peer ID is required")
	}
	parsed, err := ParseDeviceSPIFFEID(record.SPIFFEID)
	if err != nil {
		return fmt.Errorf("parse SPIFFE ID: %w", err)
	}
	if parsed.PeerID != record.PeerID {
		return ErrMismatchedSPIFFEID
	}
	expectedURL := (&url.URL{
		Scheme: "spiffe",
		Host:   parsed.TrustDomain,
		Path:   DeviceSPIFFEPathPrefix + record.PeerID,
	}).String()
	if record.SPIFFEID != expectedURL {
		return ErrMismatchedSPIFFEID
	}
	return nil
}

func validateTPMHandle(handle uint32) error {
	if handle < firstPersistentHandle || handle > lastPersistentHandle {
		return fmt.Errorf(
			"TPM handle 0x%08x is not in the persistent handle range",
			handle,
		)
	}
	return nil
}
