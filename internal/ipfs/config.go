// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package ipfs

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

const (
	// DefaultRepositoryPath is the only production Kubo repository location
	// named by v5.
	DefaultRepositoryPath = "/var/lib/sovereignite/ipfs"
	// DefaultRuntimePath contains boot-scoped IPFS readiness state only.
	DefaultRuntimePath = "/run/sovereignite/ipfs"

	publicationStateFilename = "sovereignite-publication.json"
	publicationLockFilename  = "sovereignite-publication.lock"
	serviceLockFilename      = "service.lock"
	readinessFilename        = "ready.json"
)

// RecordPolicy bounds creation and acceptance of signed publication records.
// These are safety limits for the pre-signed record boundary; D-011 still
// blocks claims that a particular mirrored protocol is authoritative.
type RecordPolicy struct {
	Validity     time.Duration
	MaxValidity  time.Duration
	MaxStaleness time.Duration
	ClockSkew    time.Duration
}

// DefaultRecordPolicy returns conservative, explicit freshness bounds.
func DefaultRecordPolicy() RecordPolicy {
	const day = 24 * time.Hour
	return RecordPolicy{
		Validity:     day,
		MaxValidity:  day,
		MaxStaleness: day,
		ClockSkew:    2 * time.Minute,
	}
}

// Validate rejects unbounded, sub-second, or internally inconsistent record
// policy. Whole-second values keep signed bytes canonical across restarts.
func (p RecordPolicy) Validate() error {
	var errs []error
	if p.Validity <= 0 {
		errs = append(errs, errors.New("record validity must be positive"))
	}
	if p.MaxValidity <= 0 {
		errs = append(errs, errors.New("maximum record validity must be positive"))
	}
	if p.MaxStaleness <= 0 {
		errs = append(errs, errors.New("maximum record staleness must be positive"))
	}
	if p.ClockSkew < 0 {
		errs = append(errs, errors.New("record clock skew cannot be negative"))
	}
	if p.Validity > p.MaxValidity {
		errs = append(errs, errors.New("record validity exceeds its maximum"))
	}
	for label, value := range map[string]time.Duration{
		"record validity":         p.Validity,
		"maximum record validity": p.MaxValidity,
		"maximum record staleness": p.MaxStaleness,
		"record clock skew":       p.ClockSkew,
	} {
		if value%time.Second != 0 {
			errs = append(
				errs,
				fmt.Errorf("%s must be a whole number of seconds", label),
			)
		}
	}
	return errors.Join(errs...)
}

// Config controls durable Kubo and boot-scoped readiness locations.
type Config struct {
	RepositoryPath string
	RuntimePath    string
	RecordPolicy   RecordPolicy
}

// DefaultConfig returns the exact production paths required by v5.
func DefaultConfig() Config {
	return Config{
		RepositoryPath: DefaultRepositoryPath,
		RuntimePath:    DefaultRuntimePath,
		RecordPolicy:   DefaultRecordPolicy(),
	}
}

// Validate rejects relative, broad, or overlapping state roots.
func (c Config) Validate() error {
	var errs []error
	repositoryErr := validateServiceRoot(c.RepositoryPath)
	if repositoryErr != nil {
		errs = append(
			errs,
			fmt.Errorf("kubo repository path: %w", repositoryErr),
		)
	}
	runtimeErr := validateServiceRoot(c.RuntimePath)
	if runtimeErr != nil {
		errs = append(errs, fmt.Errorf("runtime path: %w", runtimeErr))
	}
	if repositoryErr == nil && runtimeErr == nil &&
		rootsOverlap(c.RepositoryPath, c.RuntimePath) {
		errs = append(
			errs,
			errors.New("kubo repository and runtime paths must not overlap"),
		)
	}
	if err := c.RecordPolicy.Validate(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func validateServiceRoot(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("path is required")
	}
	if !filepath.IsAbs(path) {
		return errors.New("path must be absolute")
	}
	cleaned := filepath.Clean(path)
	if cleaned == string(filepath.Separator) {
		return errors.New("filesystem root is not allowed")
	}
	if cleaned == filepath.Dir(cleaned) {
		return errors.New("path must name a bounded directory")
	}
	return nil
}

func rootsOverlap(left, right string) bool {
	return pathWithin(left, right) || pathWithin(right, left)
}

func pathWithin(root, candidate string) bool {
	relative, err := filepath.Rel(
		filepath.Clean(root),
		filepath.Clean(candidate),
	)
	if err != nil || filepath.IsAbs(relative) {
		return false
	}
	return relative == "." ||
		(relative != ".." &&
			!strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}
