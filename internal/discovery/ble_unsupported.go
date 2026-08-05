// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

//go:build !linux

package discovery

import "errors"

func dialSystemBlueZ() (blueZSession, error) {
	return nil, errors.New("BlueZ system bus transport is supported only on Linux")
}
