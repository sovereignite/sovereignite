// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package discovery

import (
	"errors"
	"fmt"
	"strings"
)

const (
	// TXTDeviceIDKey is the sole TXT key used for the device identifier.
	TXTDeviceIDKey = "device_id"
	// TXTTrustDomainKey is the sole TXT key used for the SPIFFE trust domain.
	TXTTrustDomainKey = "trust_domain"
	// TXTAdoptionStateKey is the sole TXT key used for the adoption state.
	TXTAdoptionStateKey = "adoption_state"

	maxTXTStringBytes = 255
	maxDeviceIDBytes  = 63
	maxDNSNameBytes   = 253
)

// AdoptionState is the adoption state published during discovery.
type AdoptionState string

const (
	// AdoptionStateUnadopted identifies a device that has not been adopted.
	AdoptionStateUnadopted AdoptionState = "unadopted"
	// AdoptionStateAdopted identifies a device that has been adopted.
	AdoptionStateAdopted AdoptionState = "adopted"
)

// Record contains the complete public discovery TXT data. No other TXT fields
// are part of the discovery contract.
type Record struct {
	DeviceID      string
	TrustDomain   string
	AdoptionState AdoptionState
}

// NewRecord validates and returns a discovery record.
func NewRecord(deviceID, trustDomain string, adoptionState AdoptionState) (Record, error) {
	record := Record{
		DeviceID:      deviceID,
		TrustDomain:   trustDomain,
		AdoptionState: adoptionState,
	}
	if err := record.Validate(); err != nil {
		return Record{}, err
	}
	return record, nil
}

// Validate checks that the record has canonical values that fit individual
// DNS-SD TXT strings.
func (r Record) Validate() error {
	var errs []error
	if err := validateDeviceID(r.DeviceID); err != nil {
		errs = append(errs, fmt.Errorf("%s: %w", TXTDeviceIDKey, err))
	}
	if err := validateTrustDomain(r.TrustDomain); err != nil {
		errs = append(errs, fmt.Errorf("%s: %w", TXTTrustDomainKey, err))
	}
	switch r.AdoptionState {
	case AdoptionStateUnadopted, AdoptionStateAdopted:
	default:
		errs = append(errs, fmt.Errorf(
			"%s: must be %q or %q",
			TXTAdoptionStateKey,
			AdoptionStateUnadopted,
			AdoptionStateAdopted,
		))
	}
	fields := [...]struct {
		key   string
		value string
	}{
		{key: TXTDeviceIDKey, value: r.DeviceID},
		{key: TXTTrustDomainKey, value: r.TrustDomain},
		{key: TXTAdoptionStateKey, value: string(r.AdoptionState)},
	}
	for _, field := range fields {
		if len(field.key)+1+len(field.value) > maxTXTStringBytes {
			errs = append(
				errs,
				fmt.Errorf(
					"%s: encoded TXT string exceeds %d bytes",
					field.key,
					maxTXTStringBytes,
				),
			)
		}
	}
	return errors.Join(errs...)
}

// Encode returns the three planned TXT strings in a stable order.
func (r Record) Encode() ([]string, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return []string{
		TXTDeviceIDKey + "=" + r.DeviceID,
		TXTTrustDomainKey + "=" + r.TrustDomain,
		TXTAdoptionStateKey + "=" + string(r.AdoptionState),
	}, nil
}

// DecodeRecord decodes exactly the three planned TXT strings. Input order does
// not affect the decoded record; Encode always restores the canonical order.
func DecodeRecord(txt []string) (Record, error) {
	if len(txt) != 3 {
		return Record{}, errors.New("discovery TXT data must contain exactly three strings")
	}

	values := make(map[string]string, len(txt))
	for _, item := range txt {
		if len(item) > maxTXTStringBytes {
			return Record{}, fmt.Errorf("discovery TXT string exceeds %d bytes", maxTXTStringBytes)
		}
		key, value, ok := strings.Cut(item, "=")
		if !ok {
			return Record{}, fmt.Errorf("discovery TXT string %q has no value separator", item)
		}
		switch key {
		case TXTDeviceIDKey, TXTTrustDomainKey, TXTAdoptionStateKey:
		default:
			return Record{}, fmt.Errorf("unplanned discovery TXT key %q", key)
		}
		if _, duplicate := values[key]; duplicate {
			return Record{}, fmt.Errorf("duplicate discovery TXT key %q", key)
		}
		values[key] = value
	}

	record := Record{
		DeviceID:      values[TXTDeviceIDKey],
		TrustDomain:   values[TXTTrustDomainKey],
		AdoptionState: AdoptionState(values[TXTAdoptionStateKey]),
	}
	if err := record.Validate(); err != nil {
		return Record{}, err
	}
	return record, nil
}

func validateDeviceID(deviceID string) error {
	if deviceID == "" {
		return errors.New("is required")
	}
	if len(deviceID) > maxDeviceIDBytes {
		return fmt.Errorf("must not exceed %d bytes", maxDeviceIDBytes)
	}
	if !isDNSLabel(deviceID) {
		return errors.New("must be a canonical lowercase DNS label")
	}
	return nil
}

func validateTrustDomain(trustDomain string) error {
	if trustDomain == "" {
		return errors.New("is required")
	}
	if len(trustDomain) > maxDNSNameBytes {
		return fmt.Errorf("must not exceed %d bytes", maxDNSNameBytes)
	}
	if strings.HasPrefix(trustDomain, ".") || strings.HasSuffix(trustDomain, ".") {
		return errors.New("must not have a leading or trailing dot")
	}
	for _, label := range strings.Split(trustDomain, ".") {
		if !isDNSLabel(label) {
			return errors.New("must be a canonical lowercase DNS name")
		}
	}
	return nil
}

func isDNSLabel(value string) bool {
	if value == "" || len(value) > maxDeviceIDBytes || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') &&
			character != '-' {
			return false
		}
	}
	return true
}
