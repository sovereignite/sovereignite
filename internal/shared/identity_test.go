package shared

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"
)

func TestDeriveULA(t *testing.T) {
	ula, err := DeriveULA(ProjectName)
	if err != nil {
		t.Fatalf("DeriveULA: %v", err)
	}
	expected := net.IPNet{
		IP:   net.IP{0xfd, 0x7b, 0x0a, 0xf7, 0xff, 0x4a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		Mask: net.CIDRMask(48, 128),
	}
	if ula.String() != expected.String() {
		t.Errorf("ULA mismatch: have %s, want %s", ula, expected)
	}
}

func TestDerivePeerID(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pid, err := DerivePeerID(pub)
	if err != nil {
		t.Fatalf("DerivePeerID: %v", err)
	}
	if pid == "" {
		t.Error("empty peer ID")
	}
	pid2, err := DerivePeerID(pub)
	if err != nil {
		t.Fatalf("DerivePeerID second call: %v", err)
	}
	if pid != pid2 {
		t.Errorf("non-deterministic peer ID: %s != %s", pid, pid2)
	}
}

func TestDeriveIPNSName(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pid, err := DerivePeerID(pub)
	if err != nil {
		t.Fatalf("DerivePeerID: %v", err)
	}
	name, err := DeriveIPNSName(pid)
	if err != nil {
		t.Fatalf("DeriveIPNSName: %v", err)
	}
	if name == "" {
		t.Error("empty IPNS name")
	}
	if len(name) < 10 {
		t.Errorf("IPNS name too short: %q", name)
	}
}

func TestDeriveIdentityRoundTrip(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	id, err := DeriveIdentity(pub)
	if err != nil {
		t.Fatalf("DeriveIdentity: %v", err)
	}
	if err := ValidateIdentity(id); err != nil {
		t.Errorf("ValidateIdentity: %v", err)
	}
}

func TestValidateIdentityRejectsNil(t *testing.T) {
	if err := ValidateIdentity(nil); err == nil {
		t.Error("expected error for nil identity")
	}
}

func TestValidateIdentityRejectsCorruptedPeerID(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	id, err := DeriveIdentity(pub)
	if err != nil {
		t.Fatalf("DeriveIdentity: %v", err)
	}
	corrupted := *id
	corrupted.PeerID = "QmFakePeerID"
	if err := ValidateIdentity(&corrupted); err == nil {
		t.Error("expected error for corrupted peer ID")
	}
}

func TestValidateIdentityRejectsWrongKey(t *testing.T) {
	pub1, _, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	id1, _ := DeriveIdentity(pub1)
	_ = pub2
	if err := ValidateIdentity(id1); err != nil {
		t.Fatalf("ValidateIdentity should pass: %v", err)
	}
}
