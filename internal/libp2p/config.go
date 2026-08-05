// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package libp2p

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

const (
	// DefaultStateRoot contains the lifetime-stable public identity metadata.
	DefaultStateRoot = "/var/lib/sovereignite/identity"
	// DefaultRuntimeRoot contains only boot-scoped readiness metadata.
	DefaultRuntimeRoot = "/run/sovereignite/identity"

	identityStateFilename  = "identity.json"
	endpointRecordFilename = "endpoint.json"
	runtimeLockFilename    = "service.lock"
)

// Config controls persistent and boot-scoped identity metadata locations. The
// listener address is deliberately not configurable: the readiness listener is
// always bound to an ephemeral IPv4 loopback port.
type Config struct {
	StateRoot   string
	RuntimeRoot string
}

// DefaultConfig returns the production filesystem layout.
func DefaultConfig() Config {
	return Config{
		StateRoot:   DefaultStateRoot,
		RuntimeRoot: DefaultRuntimeRoot,
	}
}

// Validate rejects ambiguous or overly broad metadata roots.
func (c Config) Validate() error {
	var errs []error
	stateErr := validateRoot(c.StateRoot)
	if stateErr != nil {
		errs = append(errs, fmt.Errorf("state root: %w", stateErr))
	}
	runtimeErr := validateRoot(c.RuntimeRoot)
	if runtimeErr != nil {
		errs = append(errs, fmt.Errorf("runtime root: %w", runtimeErr))
	}
	if stateErr == nil && runtimeErr == nil &&
		rootsOverlap(c.StateRoot, c.RuntimeRoot) {
		errs = append(
			errs,
			errors.New("state and runtime roots must not overlap"),
		)
	}
	return errors.Join(errs...)
}

func rootsOverlap(first, second string) bool {
	return pathWithin(first, second) || pathWithin(second, first)
}

func pathWithin(root, candidate string) bool {
	relative, err := filepath.Rel(filepath.Clean(root), filepath.Clean(candidate))
	if err != nil || filepath.IsAbs(relative) {
		return false
	}
	return relative == "." ||
		(relative != ".." && !strings.HasPrefix(
			relative,
			".."+string(filepath.Separator),
		))
}

func validateRoot(root string) error {
	if strings.TrimSpace(root) == "" {
		return errors.New("path is required")
	}
	if !filepath.IsAbs(root) {
		return errors.New("path must be absolute")
	}
	if filepath.Clean(root) == string(filepath.Separator) {
		return errors.New("filesystem root is not allowed")
	}
	return nil
}

func (c Config) statePath() string {
	return filepath.Join(filepath.Clean(c.StateRoot), identityStateFilename)
}

func (c Config) endpointPath() string {
	return filepath.Join(filepath.Clean(c.RuntimeRoot), endpointRecordFilename)
}

func (c Config) runtimeLockPath() string {
	return filepath.Join(filepath.Clean(c.RuntimeRoot), runtimeLockFilename)
}
