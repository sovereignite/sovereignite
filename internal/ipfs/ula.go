// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package ipfs

import (
	"crypto/sha256"
	"errors"
	"net/netip"
)

// ULAForIPNSIdentifier deterministically maps a canonical binary IPNS
// identifier to an IPv6 unique-local /48. Callers must decode any textual IPNS
// representation before calling this function.
func ULAForIPNSIdentifier(identifier []byte) (netip.Prefix, error) {
	if len(identifier) == 0 {
		return netip.Prefix{}, errors.New("IPNS identifier must not be empty")
	}

	const domainSeparator = "github.com/sovereignite/sovereignite/ula/v1\x00"

	hash := sha256.New()
	_, _ = hash.Write([]byte(domainSeparator))
	_, _ = hash.Write(identifier)
	sum := hash.Sum(nil)

	var address [16]byte
	address[0] = 0xfd
	copy(address[1:6], sum[:5])

	return netip.PrefixFrom(netip.AddrFrom16(address), 48), nil
}
