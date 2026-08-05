// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package libp2p

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAnchoredMetadataRootPreventsPathSwapEscape(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	if err := os.MkdirAll(config.StateRoot, 0o700); err != nil {
		t.Fatalf("create metadata root: %v", err)
	}
	root, err := openPrivateDirectory(config.StateRoot)
	if err != nil {
		t.Fatalf("open anchored metadata root: %v", err)
	}
	defer func() {
		_ = root.Close()
	}()

	base := filepath.Dir(config.StateRoot)
	moved := filepath.Join(base, "moved-metadata")
	escape := filepath.Join(base, "escape-target")
	if err := os.Rename(config.StateRoot, moved); err != nil {
		t.Fatalf("rename metadata root during operation: %v", err)
	}
	if err := os.Mkdir(escape, 0o700); err != nil {
		t.Fatalf("create escape target: %v", err)
	}
	if err := os.Symlink(escape, config.StateRoot); err != nil {
		t.Fatalf("replace metadata path with symlink: %v", err)
	}

	content := []byte("anchored write\n")
	if err := atomicReplace(root, "record.json", content, 0o600); err != nil {
		t.Fatalf("write through anchored metadata root: %v", err)
	}
	persisted, err := os.ReadFile(filepath.Join(moved, "record.json"))
	if err != nil {
		t.Fatalf("read record from anchored directory: %v", err)
	}
	if string(persisted) != string(content) {
		t.Fatalf("anchored content = %q, want %q", persisted, content)
	}
	if _, err := os.Stat(filepath.Join(escape, "record.json")); !errors.Is(
		err,
		os.ErrNotExist,
	) {
		t.Fatalf("metadata operation escaped through replacement path: %v", err)
	}
}

func TestOpenPrivateDirectoryRejectsCreationUnderUntrustedParent(t *testing.T) {
	t.Parallel()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve test root: %v", err)
	}
	untrusted := filepath.Join(base, "untrusted")
	if err := os.Mkdir(untrusted, 0o700); err != nil {
		t.Fatalf("create untrusted parent: %v", err)
	}
	if err := os.Chmod(untrusted, 0o777); err != nil {
		t.Fatalf("make parent permissive: %v", err)
	}
	target := filepath.Join(untrusted, "identity")
	if root, err := openPrivateDirectory(target); err == nil {
		_ = root.Close()
		t.Fatal("metadata root was created beneath an untrusted parent")
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("metadata target exists after rejected creation: %v", err)
	}
}

func TestAtomicEndpointReplacementNeverExposesPartialContent(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	if err := os.MkdirAll(config.RuntimeRoot, 0o700); err != nil {
		t.Fatalf("create runtime root: %v", err)
	}
	root, err := openPrivateDirectory(config.RuntimeRoot)
	if err != nil {
		t.Fatalf("open runtime root: %v", err)
	}
	defer func() {
		_ = root.Close()
	}()
	first := append([]byte("first:"), bytes.Repeat([]byte("a"), 32*1024)...)
	second := append([]byte("second:"), bytes.Repeat([]byte("b"), 48*1024)...)
	if err := atomicReplace(
		root,
		endpointRecordFilename,
		first,
		0o600,
	); err != nil {
		t.Fatalf("write initial endpoint: %v", err)
	}

	readerReady := make(chan struct{})
	stop := make(chan struct{})
	readerResult := make(chan error, 1)
	go func() {
		announced := false
		for {
			content, err := os.ReadFile(config.endpointPath())
			if err != nil {
				readerResult <- err
				return
			}
			if !bytes.Equal(content, first) && !bytes.Equal(content, second) {
				readerResult <- errors.New("observed partial endpoint content")
				return
			}
			if !announced {
				close(readerReady)
				announced = true
			}
			select {
			case <-stop:
				readerResult <- nil
				return
			default:
			}
		}
	}()
	select {
	case <-readerReady:
	case <-time.After(2 * time.Second):
		close(stop)
		t.Fatal("endpoint reader did not start")
	}
	for replacement := 0; replacement < 32; replacement++ {
		content := first
		if replacement%2 == 0 {
			content = second
		}
		if err := atomicReplace(
			root,
			endpointRecordFilename,
			content,
			0o600,
		); err != nil {
			close(stop)
			<-readerResult
			t.Fatalf("replace endpoint atomically: %v", err)
		}
	}
	close(stop)
	if err := <-readerResult; err != nil {
		t.Fatalf("endpoint atomic-visibility reader: %v", err)
	}
}
