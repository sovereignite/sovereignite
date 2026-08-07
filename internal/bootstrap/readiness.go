// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const preparedServiceName = "bootstrap-prepared"

// PreparedPublisher owns the boot-scoped systemd readiness record. Prepared
// means steps 1–5 are durably verified; it never means cluster complete.
type PreparedPublisher interface {
	Publish(context.Context) error
	Verify(context.Context) error
}

// FilePreparedPublisher writes the exact record consumed by
// sovereignite-wait-ready.
type FilePreparedPublisher struct {
	path       string
	bootIDPath string
}

// NewFilePreparedPublisher constructs a publisher. bootIDPath is injectable
// for deterministic tests; production uses /proc/sys/kernel/random/boot_id.
func NewFilePreparedPublisher(
	path string,
	bootIDPath string,
) (*FilePreparedPublisher, error) {
	if path == "" {
		return nil, errors.New("prepared readiness path is required")
	}
	if bootIDPath == "" {
		return nil, errors.New("kernel boot ID path is required")
	}
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve prepared readiness path: %w", err)
	}
	absoluteBootIDPath, err := filepath.Abs(bootIDPath)
	if err != nil {
		return nil, fmt.Errorf("resolve kernel boot ID path: %w", err)
	}
	return &FilePreparedPublisher{
		path:       absolutePath,
		bootIDPath: absoluteBootIDPath,
	}, nil
}

// Publish atomically replaces and syncs the current-boot readiness record.
func (p *FilePreparedPublisher) Publish(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	content, err := p.expectedContent()
	if err != nil {
		return err
	}
	directory := filepath.Dir(p.path)
	if err := ensurePrivateDirectory(directory); err != nil {
		return err
	}
	if _, err := secureRegularFile(p.path); err != nil &&
		!errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary, err := os.CreateTemp(
		directory,
		"."+filepath.Base(p.path)+".tmp-*",
	)
	if err != nil {
		return fmt.Errorf("create prepared readiness temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("set prepared readiness permissions: %w", err)
	}
	if _, err := io.Copy(temporary, bytes.NewReader(content)); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write prepared readiness: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync prepared readiness: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close prepared readiness: %w", err)
	}
	if err := os.Rename(temporaryPath, p.path); err != nil {
		return fmt.Errorf("replace prepared readiness: %w", err)
	}
	directoryFile, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open prepared readiness directory for sync: %w", err)
	}
	syncErr := directoryFile.Sync()
	closeErr := directoryFile.Close()
	if syncErr != nil {
		return fmt.Errorf("sync prepared readiness directory: %w", syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close prepared readiness directory: %w", closeErr)
	}
	return nil
}

// Verify checks that the exact current-boot record is present and owner-only.
func (p *FilePreparedPublisher) Verify(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	expected, err := p.expectedContent()
	if err != nil {
		return err
	}
	info, err := secureRegularFile(p.path)
	if err != nil {
		return fmt.Errorf("inspect prepared readiness: %w", err)
	}
	if info.Mode().Perm() != 0o600 {
		return fmt.Errorf(
			"prepared readiness permissions are %04o, expected 0600",
			info.Mode().Perm(),
		)
	}
	if info.Size() != int64(len(expected)) {
		return errors.New("prepared readiness has an unexpected size")
	}
	content, err := os.ReadFile(p.path)
	if err != nil {
		return fmt.Errorf("read prepared readiness: %w", err)
	}
	if !bytes.Equal(content, expected) {
		return errors.New("prepared readiness does not match the current boot")
	}
	return nil
}

func (p *FilePreparedPublisher) expectedContent() ([]byte, error) {
	bootIDContent, err := os.ReadFile(p.bootIDPath)
	if err != nil {
		return nil, fmt.Errorf("read kernel boot ID: %w", err)
	}
	bootID := strings.TrimSuffix(string(bootIDContent), "\n")
	if !validBootID(bootID) {
		return nil, errors.New("kernel boot ID is malformed")
	}
	return []byte(fmt.Sprintf(
		`{"version":1,"service":"%s","boot_id":"%s","ready":true}`,
		preparedServiceName,
		bootID,
	)), nil
}

func validBootID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, character := range value {
		switch index {
		case 8, 13, 18, 23:
			if character != '-' {
				return false
			}
		default:
			if (character < '0' || character > '9') &&
				(character < 'a' || character > 'f') {
				return false
			}
		}
	}
	return true
}
