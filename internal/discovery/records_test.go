// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package discovery

import (
	"reflect"
	"strings"
	"testing"
)

func TestRecordEncodeUsesOnlyPlannedKeysInCanonicalOrder(t *testing.T) {
	t.Parallel()

	record, err := NewRecord("bafzaajaiaejcbnode1", "mesh.example", AdoptionStateUnadopted)
	if err != nil {
		t.Fatal(err)
	}

	got, err := record.Encode()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"device_id=bafzaajaiaejcbnode1",
		"trust_domain=mesh.example",
		"adoption_state=unadopted",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Encode() = %#v, want %#v", got, want)
	}
}

func TestDecodeRecordAcceptsInputOrderAndReencodesCanonically(t *testing.T) {
	t.Parallel()

	record, err := DecodeRecord([]string{
		"adoption_state=adopted",
		"device_id=node-7",
		"trust_domain=mesh.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	if record.AdoptionState != AdoptionStateAdopted {
		t.Fatalf("adoption state = %q, want %q", record.AdoptionState, AdoptionStateAdopted)
	}

	got, err := record.Encode()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"device_id=node-7",
		"trust_domain=mesh.example",
		"adoption_state=adopted",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("canonical TXT = %#v, want %#v", got, want)
	}
}

func TestRecordValidationRejectsNoncanonicalValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		record Record
	}{
		{
			name: "missing device ID",
			record: Record{
				TrustDomain:   "mesh.example",
				AdoptionState: AdoptionStateUnadopted,
			},
		},
		{
			name: "uppercase device ID",
			record: Record{
				DeviceID:      "Node-7",
				TrustDomain:   "mesh.example",
				AdoptionState: AdoptionStateUnadopted,
			},
		},
		{
			name: "oversized device ID",
			record: Record{
				DeviceID:      strings.Repeat("a", maxDeviceIDBytes+1),
				TrustDomain:   "mesh.example",
				AdoptionState: AdoptionStateUnadopted,
			},
		},
		{
			name: "noncanonical trust domain",
			record: Record{
				DeviceID:      "node-7",
				TrustDomain:   "Mesh.Example",
				AdoptionState: AdoptionStateUnadopted,
			},
		},
		{
			name: "empty trust-domain label",
			record: Record{
				DeviceID:      "node-7",
				TrustDomain:   "mesh..example",
				AdoptionState: AdoptionStateUnadopted,
			},
		},
		{
			name: "intermediate adoption state",
			record: Record{
				DeviceID:      "node-7",
				TrustDomain:   "mesh.example",
				AdoptionState: "pending",
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := test.record.Validate(); err == nil {
				t.Fatal("Validate() succeeded, want error")
			}
		})
	}
}

func TestDecodeRecordRejectsUnplannedMalformedAndDuplicateFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		txt  []string
	}{
		{
			name: "extra field",
			txt: []string{
				"device_id=node-7",
				"trust_domain=mesh.example",
				"adoption_state=unadopted",
				"endpoint=https://example.invalid",
			},
		},
		{
			name: "unknown field replacing planned field",
			txt: []string{
				"device_id=node-7",
				"trust_domain=mesh.example",
				"state=unadopted",
			},
		},
		{
			name: "duplicate field",
			txt: []string{
				"device_id=node-7",
				"device_id=node-8",
				"adoption_state=unadopted",
			},
		},
		{
			name: "missing separator",
			txt: []string{
				"device_id=node-7",
				"trust_domain",
				"adoption_state=unadopted",
			},
		},
		{
			name: "unplanned adoption state",
			txt: []string{
				"device_id=node-7",
				"trust_domain=mesh.example",
				"adoption_state=adopting",
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := DecodeRecord(test.txt); err == nil {
				t.Fatal("DecodeRecord() succeeded, want error")
			}
		})
	}
}

func TestDecodeRecordRejectsStaleFormatRecords(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		txt  []string
	}{
		{
			name: "hypothetical previous version field",
			txt: []string{
				"device_id=node-7",
				"trust_domain=mesh.example",
				"adoption_state=unadopted",
				"version=1",
			},
		},
		{
			name: "renamed field from older format",
			txt: []string{
				"device_id=node-7",
				"trust_domain=mesh.example",
				"adoption_state=unadopted",
				"host=node-7",
			},
		},
		{
			name: "field count mismatch (too few)",
			txt: []string{
				"device_id=node-7",
				"trust_domain=mesh.example",
			},
		},
		{
			name: "field count mismatch (too many)",
			txt: []string{
				"device_id=node-7",
				"trust_domain=mesh.example",
				"adoption_state=unadopted",
				"extra=value",
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := DecodeRecord(test.txt); err == nil {
				t.Fatal("DecodeRecord() succeeded, want error for stale/malformed record")
			}
		})
	}
}

func TestDecodeRecordRejectsOversizedRecords(t *testing.T) {
	t.Parallel()

	oversizedDeviceID := strings.Repeat("a", maxDeviceIDBytes+1)
	oversizedTrustDomain := strings.Repeat("a", maxDNSNameBytes+1)

	tests := []struct {
		name   string
		record Record
	}{
		{
			name: "oversized device ID",
			record: Record{
				DeviceID:      oversizedDeviceID,
				TrustDomain:   "mesh.example",
				AdoptionState: AdoptionStateUnadopted,
			},
		},
		{
			name: "oversized trust domain",
			record: Record{
				DeviceID:      "node-7",
				TrustDomain:   oversizedTrustDomain,
				AdoptionState: AdoptionStateUnadopted,
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := test.record.Validate(); err == nil {
				t.Fatal("Validate() succeeded, want error for oversized record")
			}
			if _, err := test.record.Encode(); err == nil {
				t.Fatal("Encode() succeeded, want error for oversized record")
			}
		})
	}
}

func TestDecodeRecordRejectsEmptyValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		txt  []string
	}{
		{
			name: "empty device ID",
			txt: []string{
				"device_id=",
				"trust_domain=mesh.example",
				"adoption_state=unadopted",
			},
		},
		{
			name: "empty trust domain",
			txt: []string{
				"device_id=node-7",
				"trust_domain=",
				"adoption_state=unadopted",
			},
		},
		{
			name: "empty adoption state",
			txt: []string{
				"device_id=node-7",
				"trust_domain=mesh.example",
				"adoption_state=",
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := DecodeRecord(test.txt); err == nil {
				t.Fatal("DecodeRecord() succeeded, want error for empty value")
			}
		})
	}
}

func TestDecodeRecordRejectsMismatchedData(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		txt  []string
	}{
		{
			name: "device ID with uppercase",
			txt: []string{
				"device_id=Node-7",
				"trust_domain=mesh.example",
				"adoption_state=unadopted",
			},
		},
		{
			name: "trust domain with uppercase",
			txt: []string{
				"device_id=node-7",
				"trust_domain=Mesh.Example",
				"adoption_state=unadopted",
			},
		},
		{
			name: "trust domain with leading dot",
			txt: []string{
				"device_id=node-7",
				"trust_domain=.mesh.example",
				"adoption_state=unadopted",
			},
		},
		{
			name: "trust domain with trailing dot",
			txt: []string{
				"device_id=node-7",
				"trust_domain=mesh.example.",
				"adoption_state=unadopted",
			},
		},
		{
			name: "device ID with spaces",
			txt: []string{
				"device_id=node 7",
				"trust_domain=mesh.example",
				"adoption_state=unadopted",
			},
		},
		{
			name: "device ID starting with hyphen",
			txt: []string{
				"device_id=-node7",
				"trust_domain=mesh.example",
				"adoption_state=unadopted",
			},
		},
		{
			name: "device ID ending with hyphen",
			txt: []string{
				"device_id=node7-",
				"trust_domain=mesh.example",
				"adoption_state=unadopted",
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := DecodeRecord(test.txt); err == nil {
				t.Fatal("DecodeRecord() succeeded, want error for mismatched data")
			}
		})
	}
}

func TestRecordTXTStringLengthBoundary(t *testing.T) {
	t.Parallel()

	maximumTrustDomain := strings.Join([]string{
		strings.Repeat("a", 63),
		strings.Repeat("b", 63),
		strings.Repeat("c", 63),
		strings.Repeat("d", 50),
	}, ".")
	if len(TXTTrustDomainKey)+1+len(maximumTrustDomain) != maxTXTStringBytes {
		t.Fatal("test trust domain does not reach the TXT string boundary")
	}
	record, err := NewRecord("node-7", maximumTrustDomain, AdoptionStateUnadopted)
	if err != nil {
		t.Fatalf("maximum-sized TXT value rejected: %v", err)
	}
	if _, err := record.Encode(); err != nil {
		t.Fatalf("maximum-sized TXT value failed encoding: %v", err)
	}

	oversizedTrustDomain := maximumTrustDomain + "e"
	if _, err := NewRecord(
		"node-7",
		oversizedTrustDomain,
		AdoptionStateUnadopted,
	); err == nil {
		t.Fatal("oversized TXT value accepted")
	}
}
