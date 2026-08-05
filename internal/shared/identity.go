package shared

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"net"

	"github.com/ipfs/go-cid"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multihash"
)

const ProjectName = "sovereignite"

type Identity struct {
	PublicKeyDER []byte
	PeerID       peer.ID
	IPNSName     string
	ULAPrefix    net.IPNet
}

func DerivePeerID(pub ed25519.PublicKey) (peer.ID, error) {
	if len(pub) != ed25519.PublicKeySize {
		return "", fmt.Errorf("invalid Ed25519 public key size: %d", len(pub))
	}
	libp2pKey, err := libp2pKeyFromEd25519(pub)
	if err != nil {
		return "", fmt.Errorf("encode libp2p key: %w", err)
	}
	mh, err := multihash.Sum(libp2pKey, multihash.SHA2_256, -1)
	if err != nil {
		return "", fmt.Errorf("multihash key: %w", err)
	}
	pid, err := peer.IDFromBytes(mh)
	if err != nil {
		return "", fmt.Errorf("peer ID from multihash: %w", err)
	}
	return pid, nil
}

func DeriveIPNSName(pid peer.ID) (string, error) {
	c := cid.NewCidV1(0x0055, multihash.Multihash(pid))
	encoded, err := multibase.Encode(multibase.Base36, c.Bytes())
	if err != nil {
		return "", fmt.Errorf("base36 encode CID: %w", err)
	}
	return encoded, nil
}

func DeriveULA(project string) (net.IPNet, error) {
	h := sha256.Sum256([]byte(project))
	if len(h) < 5 {
		return net.IPNet{}, fmt.Errorf("hash too short")
	}
	ip := make(net.IP, 16)
	ip[0] = 0xfd
	copy(ip[1:6], h[0:5])
	return net.IPNet{
		IP:   ip,
		Mask: net.CIDRMask(48, 128),
	}, nil
}

func DeriveIdentity(pub ed25519.PublicKey) (*Identity, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("marshal public key DER: %w", err)
	}
	pid, err := DerivePeerID(pub)
	if err != nil {
		return nil, fmt.Errorf("derive peer ID: %w", err)
	}
	ipns, err := DeriveIPNSName(pid)
	if err != nil {
		return nil, fmt.Errorf("derive IPNS name: %w", err)
	}
	ula, err := DeriveULA(ProjectName)
	if err != nil {
		return nil, fmt.Errorf("derive ULA: %w", err)
	}
	return &Identity{
		PublicKeyDER: der,
		PeerID:       pid,
		IPNSName:     ipns,
		ULAPrefix:    ula,
	}, nil
}

func ValidateIdentity(id *Identity) error {
	if id == nil {
		return fmt.Errorf("nil identity")
	}
	pub, err := x509.ParsePKIXPublicKey(id.PublicKeyDER)
	if err != nil {
		return fmt.Errorf("parse public key DER: %w", err)
	}
	edpub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not Ed25519")
	}
	expected, err := DeriveIdentity(edpub)
	if err != nil {
		return fmt.Errorf("recompute identity: %w", err)
	}
	if id.PeerID != expected.PeerID {
		return fmt.Errorf("peer ID mismatch: have %s, want %s", id.PeerID, expected.PeerID)
	}
	if id.IPNSName != expected.IPNSName {
		return fmt.Errorf("IPNS name mismatch: have %s, want %s", id.IPNSName, expected.IPNSName)
	}
	if id.ULAPrefix.String() != expected.ULAPrefix.String() {
		return fmt.Errorf("ULA mismatch: have %s, want %s", id.ULAPrefix, expected.ULAPrefix)
	}
	return nil
}

func libp2pKeyFromEd25519(pub ed25519.PublicKey) ([]byte, error) {
	return append([]byte{0xed, 0x01}, pub...), nil
}
