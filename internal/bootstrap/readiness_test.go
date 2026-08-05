// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package bootstrap

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFilePreparedPublisherWritesExactBootScopedRecord(t *testing.T) {
	t.Parallel()

	directory := secureTempDir(t)
	bootIDPath := filepath.Join(directory, "boot_id")
	const firstBootID = "00112233-4455-6677-8899-aabbccddeeff"
	if err := os.WriteFile(bootIDPath, []byte(firstBootID+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "prepared.json")
	publisher, err := NewFilePreparedPublisher(path, bootIDPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := publisher.Publish(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := publisher.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"version":1,"service":"bootstrap-prepared","boot_id":"` +
		firstBootID +
		`","ready":true}`
	if string(content) != want {
		t.Fatalf("prepared record = %q, want %q", content, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("prepared permissions = %04o, want 0600", info.Mode().Perm())
	}
}

func TestFilePreparedPublisherReplacesStaleBootRecord(t *testing.T) {
	t.Parallel()

	directory := secureTempDir(t)
	bootIDPath := filepath.Join(directory, "boot_id")
	path := filepath.Join(directory, "prepared.json")
	if err := os.WriteFile(
		bootIDPath,
		[]byte("00112233-4455-6677-8899-aabbccddeeff\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	publisher, err := NewFilePreparedPublisher(path, bootIDPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := publisher.Publish(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		bootIDPath,
		[]byte("ffeeddcc-bbaa-9988-7766-554433221100\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := publisher.Verify(context.Background()); err == nil {
		t.Fatal("Verify() accepted a prior-boot record")
	}
	if err := publisher.Publish(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := publisher.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestFilePreparedPublisherFailsClosedForMalformedBootIDAndSymlink(t *testing.T) {
	t.Parallel()

	t.Run("malformed boot ID", func(t *testing.T) {
		t.Parallel()
		directory := secureTempDir(t)
		bootIDPath := filepath.Join(directory, "boot_id")
		if err := os.WriteFile(
			bootIDPath,
			[]byte("NOT-A-BOOT-ID\n"),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
		publisher, err := NewFilePreparedPublisher(
			filepath.Join(directory, "prepared.json"),
			bootIDPath,
		)
		if err != nil {
			t.Fatal(err)
		}
		if err := publisher.Publish(context.Background()); err == nil {
			t.Fatal("Publish() accepted malformed boot ID")
		}
	})
	t.Run("prepared symlink", func(t *testing.T) {
		t.Parallel()
		directory := secureTempDir(t)
		bootIDPath := filepath.Join(directory, "boot_id")
		if err := os.WriteFile(
			bootIDPath,
			[]byte("00112233-4455-6677-8899-aabbccddeeff\n"),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(directory, "target.json")
		if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, "prepared.json")
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		publisher, err := NewFilePreparedPublisher(path, bootIDPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := publisher.Publish(context.Background()); err == nil {
			t.Fatal("Publish() followed prepared symlink")
		}
	})
}
