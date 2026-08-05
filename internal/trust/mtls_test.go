// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package trust

import (
	"crypto/tls"
	"testing"
	"time"
)

func TestVerifyMutualTLSPeerAcceptsVerifiedTLS13Client(t *testing.T) {
	t.Parallel()

	identity, private := testIdentity(t)
	state := testTLSState(t, identity, private)
	peer, err := VerifyMutualTLSPeer(state, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if peer.Identity() != identity {
		t.Fatalf("verified identity = %#v, want %#v", peer.Identity(), identity)
	}
	if len(peer.CertificateDER()) == 0 {
		t.Fatal("verified peer omitted public certificate DER")
	}
	first := peer.CertificateDER()
	first[0] ^= 0xff
	if string(first) == string(peer.CertificateDER()) {
		t.Fatal("CertificateDER returned mutable internal bytes")
	}
}

func TestVerifyMutualTLSPeerRejectsNonMutualAndInvalidTLS(t *testing.T) {
	t.Parallel()

	identity, private := testIdentity(t)
	valid := testTLSState(t, identity, private)
	tests := map[string]tls.ConnectionState{
		"incomplete": func() tls.ConnectionState {
			state := valid
			state.HandshakeComplete = false
			return state
		}(),
		"TLS 1.2": func() tls.ConnectionState {
			state := valid
			state.Version = tls.VersionTLS12
			return state
		}(),
		"server auth only": {
			Version:           tls.VersionTLS13,
			HandshakeComplete: true,
		},
		"unverified client": func() tls.ConnectionState {
			state := valid
			state.VerifiedChains = nil
			return state
		}(),
	}
	for name, state := range tests {
		name, state := name, state
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := VerifyMutualTLSPeer(state, testNow); err == nil {
				t.Fatal("VerifyMutualTLSPeer succeeded")
			}
		})
	}
	if _, err := VerifyMutualTLSPeer(valid, testNow.Add(2*time.Hour)); err == nil {
		t.Fatal("VerifyMutualTLSPeer accepted expired certificate")
	}
}
