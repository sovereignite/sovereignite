// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package endpoint

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func testRecord(service string) EndpointRecord {
	return EndpointRecord{
		Version:       RecordVersion,
		Service:       service,
		BootID:        "boot-abc",
		InstanceNonce: GenerateNonce(),
		PID:           os.Getpid(),
		Network:       "tcp",
		Address:       "127.0.0.1",
		Port:          0,
	}
}

func TestPublishAndRead(t *testing.T) {
	dir := t.TempDir()
	svcDir := NewServiceDir(dir, "keymanager")
	rec := testRecord("keymanager")
	addr, err := Publish(svcDir, rec)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}

	loaded, err := ReadRecord(svcDir)
	if err != nil {
		t.Fatalf("ReadRecord: %v", err)
	}
	if loaded.Service != "keymanager" {
		t.Errorf("Service = %q, want %q", loaded.Service, "keymanager")
	}
	if loaded.Version != RecordVersion {
		t.Errorf("Version = %d, want %d", loaded.Version, RecordVersion)
	}
	if loaded.BootID != "boot-abc" {
		t.Errorf("BootID = %q, want %q", loaded.BootID, "boot-abc")
	}
	if loaded.PID != os.Getpid() {
		t.Errorf("PID = %d, want %d", loaded.PID, os.Getpid())
	}
	if loaded.Address != "127.0.0.1" {
		t.Errorf("Address = %q, want %q", loaded.Address, "127.0.0.1")
	}
	if loaded.InstanceNonce == "" {
		t.Error("InstanceNonce is empty")
	}

	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		t.Fatalf("addr is %T, want *net.TCPAddr", addr)
	}
	if !tcpAddr.IP.IsLoopback() {
		t.Errorf("addr IP %v is not loopback", tcpAddr.IP)
	}
}

func TestPublishCreatesDirectories(t *testing.T) {
	dir := t.TempDir()
	svcDir := NewServiceDir(dir, "trust")
	rec := testRecord("trust")
	if _, err := Publish(svcDir, rec); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	fi, err := os.Stat(svcDir)
	if err != nil {
		t.Fatalf("Stat dir: %v", err)
	}
	if fi.Mode().Perm() != dirPerms {
		t.Errorf("dir perms = %o, want %o", fi.Mode().Perm(), dirPerms)
	}
}

func TestPublishAtomicOnRestart(t *testing.T) {
	dir := t.TempDir()
	svcDir := NewServiceDir(dir, "discovery")

	rec := testRecord("discovery")
	if _, err := Publish(svcDir, rec); err != nil {
		t.Fatalf("Publish first: %v", err)
	}
	rec2 := testRecord("discovery")
	if _, err := Publish(svcDir, rec2); err != nil {
		t.Fatalf("Publish second: %v", err)
	}

	loaded, err := ReadRecord(svcDir)
	if err != nil {
		t.Fatalf("ReadRecord: %v", err)
	}
	if loaded.InstanceNonce != rec2.InstanceNonce {
		t.Errorf("nonce = %q, want %q (second publish should overwrite)", loaded.InstanceNonce, rec2.InstanceNonce)
	}

	tmpFiles, _ := filepath.Glob(filepath.Join(svcDir, ".endpoint.json.tmp"))
	if len(tmpFiles) > 0 {
		t.Errorf("temp files left behind: %v", tmpFiles)
	}
}

func TestValidatePassesForMatchingRecord(t *testing.T) {
	rec := testRecord("keymanager")
	if err := Validate(rec, "boot-abc", os.Getpid(), "keymanager"); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidateRejectsStaleBootID(t *testing.T) {
	rec := testRecord("keymanager")
	err := Validate(rec, "different-boot", os.Getpid(), "keymanager")
	if !errors.Is(err, ErrStaleBootID) {
		t.Errorf("Validate err = %v, want ErrStaleBootID", err)
	}
}

func TestValidateRejectsStaleInstanceNonce(t *testing.T) {
	rec := testRecord("keymanager")
	rec.InstanceNonce = "old-nonce"
	if err := Validate(rec, "boot-abc", os.Getpid(), "keymanager"); err != nil {
		t.Fatalf("Validate should pass for stale nonce: %v", err)
	}
}

func TestValidateRejectsWrongService(t *testing.T) {
	rec := testRecord("keymanager")
	err := Validate(rec, "boot-abc", os.Getpid(), "trust")
	if !errors.Is(err, ErrWrongService) {
		t.Errorf("Validate err = %v, want ErrWrongService", err)
	}
}

func TestValidateRejectsWrongPID(t *testing.T) {
	rec := testRecord("keymanager")
	err := Validate(rec, "boot-abc", os.Getpid()+999, "keymanager")
	if !errors.Is(err, ErrPIDMismatch) {
		t.Errorf("Validate err = %v, want ErrPIDMismatch", err)
	}
}

func TestValidateRejectsNonLoopback(t *testing.T) {
	rec := testRecord("keymanager")
	rec.Address = "192.168.1.1"
	err := Validate(rec, "boot-abc", os.Getpid(), "keymanager")
	if !errors.Is(err, ErrNonLoopback) {
		t.Errorf("Validate err = %v, want ErrNonLoopback", err)
	}
}

func TestValidateRejectsBadVersion(t *testing.T) {
	rec := testRecord("keymanager")
	rec.Version = 99
	err := Validate(rec, "boot-abc", os.Getpid(), "keymanager")
	if !errors.Is(err, ErrMalformedRecord) {
		t.Errorf("Validate err = %v, want ErrMalformedRecord", err)
	}
}

func TestValidateRejectsEmptyNonce(t *testing.T) {
	rec := testRecord("keymanager")
	rec.InstanceNonce = ""
	err := Validate(rec, "boot-abc", os.Getpid(), "keymanager")
	if !errors.Is(err, ErrMalformedRecord) {
		t.Errorf("Validate err = %v, want ErrMalformedRecord", err)
	}
}

func TestValidateRejectsIPv6NonLoopback(t *testing.T) {
	rec := testRecord("keymanager")
	rec.Address = "fd00::1"
	err := Validate(rec, "boot-abc", os.Getpid(), "keymanager")
	if !errors.Is(err, ErrNonLoopback) {
		t.Errorf("Validate err = %v, want ErrNonLoopback", err)
	}
}

func TestCleanupRemovesMatchingRecord(t *testing.T) {
	dir := t.TempDir()
	svcDir := NewServiceDir(dir, "keymanager")
	rec := testRecord("keymanager")
	if _, err := Publish(svcDir, rec); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if err := Cleanup(svcDir, rec); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if _, err := os.Stat(filepath.Join(svcDir, "endpoint.json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("file still exists after cleanup, err=%v", err)
	}
}

func TestCleanupIgnoresDifferentNonce(t *testing.T) {
	dir := t.TempDir()
	svcDir := NewServiceDir(dir, "keymanager")
	rec := testRecord("keymanager")
	if _, err := Publish(svcDir, rec); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	other := testRecord("keymanager")
	other.InstanceNonce = "other-nonce"
	if err := Cleanup(svcDir, other); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if _, err := os.Stat(filepath.Join(svcDir, "endpoint.json")); err != nil {
		t.Errorf("file should still exist: %v", err)
	}
}

func TestCleanupIgnoresMissingFile(t *testing.T) {
	dir := t.TempDir()
	svcDir := NewServiceDir(dir, "keymanager")
	rec := testRecord("keymanager")
	if err := Cleanup(svcDir, rec); err != nil {
		t.Fatalf("Cleanup on missing: %v", err)
	}
}

func TestReadRecordRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	svcDir := NewServiceDir(dir, "keymanager")
	if err := os.MkdirAll(svcDir, dirPerms); err != nil {
		t.Fatal(err)
	}
	rec := testRecord("keymanager")
	data, _ := json.Marshal(rec)
	realFile := filepath.Join(svcDir, "endpoint.json.real")
	if err := os.WriteFile(realFile, data, filePerms); err != nil {
		t.Fatal(err)
	}
	linkFile := filepath.Join(svcDir, "endpoint.json")
	if err := os.Symlink(realFile, linkFile); err != nil {
		t.Fatal(err)
	}
	_, err := ReadRecord(svcDir)
	if !errors.Is(err, ErrSymlinkDetected) {
		t.Errorf("ReadRecord err = %v, want ErrSymlinkDetected", err)
	}
}

func TestReadRecordRejectsMalformedJSON(t *testing.T) {
	dir := t.TempDir()
	svcDir := NewServiceDir(dir, "keymanager")
	if err := os.MkdirAll(svcDir, dirPerms); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(svcDir, "endpoint.json")
	if err := os.WriteFile(bad, []byte("{bad json"), filePerms); err != nil {
		t.Fatal(err)
	}
	_, err := ReadRecord(svcDir)
	if !errors.Is(err, ErrMalformedRecord) {
		t.Errorf("ReadRecord err = %v, want ErrMalformedRecord", err)
	}
}

func TestConcurrentPublishSameDir(t *testing.T) {
	dir := t.TempDir()
	svcDir := NewServiceDir(dir, "keymanager")
	const N = 10
	var wg sync.WaitGroup
	errs := make(chan error, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := testRecord("keymanager")
			_, err := PublishSerialised(svcDir, rec)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent Publish: %v", err)
		}
	}
	loaded, err := ReadRecord(svcDir)
	if err != nil {
		t.Fatalf("ReadRecord: %v", err)
	}
	if loaded.Version != RecordVersion {
		t.Errorf("Version = %d, want %d", loaded.Version, RecordVersion)
	}
}

func TestConcurrentPublishDifferentDirs(t *testing.T) {
	dir := t.TempDir()
	services := []string{"keymanager", "trust", "discovery", "network", "bootstrap"}
	var wg sync.WaitGroup
	errs := make(chan error, len(services))
	for _, svc := range services {
		wg.Add(1)
		go func(s string) {
			defer wg.Done()
			svcDir := NewServiceDir(dir, s)
			rec := testRecord(s)
			_, err := Publish(svcDir, rec)
			errs <- err
		}(svc)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent Publish: %v", err)
		}
	}
	for _, svc := range services {
		svcDir := NewServiceDir(dir, svc)
		loaded, err := ReadRecord(svcDir)
		if err != nil {
			t.Errorf("ReadRecord %s: %v", svc, err)
			continue
		}
		if loaded.Service != svc {
			t.Errorf("Service = %q, want %q", loaded.Service, svc)
		}
	}
}

func TestPublishFilePermissions(t *testing.T) {
	dir := t.TempDir()
	svcDir := NewServiceDir(dir, "keymanager")
	rec := testRecord("keymanager")
	if _, err := Publish(svcDir, rec); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	fi, err := os.Stat(filepath.Join(svcDir, "endpoint.json"))
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if fi.Mode().Perm() != filePerms {
		t.Errorf("file perms = %o, want %o", fi.Mode().Perm(), filePerms)
	}
}

func TestValidateRecordFullFlow(t *testing.T) {
	dir := t.TempDir()
	svcDir := NewServiceDir(dir, "keymanager")
	rec := testRecord("keymanager")
	if _, err := Publish(svcDir, rec); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	loaded, err := ValidateRecord(svcDir, "boot-abc", os.Getpid(), "keymanager")
	if err != nil {
		t.Fatalf("ValidateRecord: %v", err)
	}
	if loaded.Service != "keymanager" {
		t.Errorf("Service = %q, want %q", loaded.Service, "keymanager")
	}
}

func TestValidateRecordStaleBoot(t *testing.T) {
	dir := t.TempDir()
	svcDir := NewServiceDir(dir, "keymanager")
	rec := testRecord("keymanager")
	if _, err := Publish(svcDir, rec); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	_, err := ValidateRecord(svcDir, "new-boot-id", os.Getpid(), "keymanager")
	if !errors.Is(err, ErrStaleBootID) {
		t.Errorf("ValidateRecord err = %v, want ErrStaleBootID", err)
	}
}

func TestRecordFromFileRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	realFile := filepath.Join(dir, "real.json")
	data := []byte(`{"version":1,"service":"test","boot_id":"b","instance_nonce":"n","pid":1,"network":"tcp","address":"127.0.0.1","port":1234}`)
	os.WriteFile(realFile, data, filePerms)
	linkFile := filepath.Join(dir, "endpoint.json")
	os.Symlink(realFile, linkFile)
	_, err := RecordFromFile(linkFile)
	if !errors.Is(err, ErrSymlinkDetected) {
		t.Errorf("RecordFromFile err = %v, want ErrSymlinkDetected", err)
	}
}

func TestGenerateNonceUniqueness(t *testing.T) {
	seen := make(map[string]bool, 1000)
	for i := 0; i < 1000; i++ {
		n := GenerateNonce()
		if seen[n] {
			t.Fatalf("duplicate nonce %q after %d iterations", n, i)
		}
		seen[n] = true
	}
}

func TestValidateRecordRejectsStaleRecordFromDifferentPID(t *testing.T) {
	dir := t.TempDir()
	svcDir := NewServiceDir(dir, "keymanager")
	rec := testRecord("keymanager")
	if _, err := Publish(svcDir, rec); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	_, err := ValidateRecord(svcDir, "boot-abc", os.Getpid()+999, "keymanager")
	if !errors.Is(err, ErrPIDMismatch) {
		t.Errorf("ValidateRecord err = %v, want ErrPIDMismatch", err)
	}
}

func TestValidateRecordRejectsNonLoopbackAddress(t *testing.T) {
	dir := t.TempDir()
	svcDir := NewServiceDir(dir, "keymanager")
	rec := testRecord("keymanager")
	rec.Address = "10.0.0.1"
	if _, err := Publish(svcDir, rec); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	_, err := ValidateRecord(svcDir, "boot-abc", os.Getpid(), "keymanager")
	if !errors.Is(err, ErrNonLoopback) {
		t.Errorf("ValidateRecord err = %v, want ErrNonLoopback", err)
	}
}

func TestValidateRecordRejectsStaleBootFromDisk(t *testing.T) {
	dir := t.TempDir()
	svcDir := NewServiceDir(dir, "keymanager")
	rec := testRecord("keymanager")
	if _, err := Publish(svcDir, rec); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	_, err := ValidateRecord(svcDir, "different-boot-id", os.Getpid(), "keymanager")
	if !errors.Is(err, ErrStaleBootID) {
		t.Errorf("ValidateRecord err = %v, want ErrStaleBootID", err)
	}
}

func TestPublishRecoversFromCrashPartialState(t *testing.T) {
	dir := t.TempDir()
	svcDir := NewServiceDir(dir, "keymanager")
	if err := os.MkdirAll(svcDir, dirPerms); err != nil {
		t.Fatal(err)
	}

	tmpFile := filepath.Join(svcDir, ".endpoint.json.tmp")
	if err := os.WriteFile(tmpFile, []byte(`{}`), filePerms); err != nil {
		t.Fatal(err)
	}

	rec := testRecord("keymanager")
	if _, err := Publish(svcDir, rec); err != nil {
		t.Fatalf("Publish after crash-partial: %v", err)
	}
	loaded, err := ReadRecord(svcDir)
	if err != nil {
		t.Fatalf("ReadRecord after crash-partial: %v", err)
	}
	if loaded.Service != "keymanager" {
		t.Errorf("Service = %q, want %q", loaded.Service, "keymanager")
	}
}

func TestReadRecordRejectsCrashPartialEmptyFile(t *testing.T) {
	dir := t.TempDir()
	svcDir := NewServiceDir(dir, "keymanager")
	if err := os.MkdirAll(svcDir, dirPerms); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(svcDir, "endpoint.json"), []byte(""), filePerms); err != nil {
		t.Fatal(err)
	}
	_, err := ReadRecord(svcDir)
	if !errors.Is(err, ErrMalformedRecord) {
		t.Errorf("ReadRecord err = %v, want ErrMalformedRecord", err)
	}
}

func TestReadRecordRejectsTruncatedJSON(t *testing.T) {
	dir := t.TempDir()
	svcDir := NewServiceDir(dir, "keymanager")
	if err := os.MkdirAll(svcDir, dirPerms); err != nil {
		t.Fatal(err)
	}
	truncated := []byte(`{"version":1,"service":"key`)
	if err := os.WriteFile(filepath.Join(svcDir, "endpoint.json"), truncated, filePerms); err != nil {
		t.Fatal(err)
	}
	_, err := ReadRecord(svcDir)
	if !errors.Is(err, ErrMalformedRecord) {
		t.Errorf("ReadRecord err = %v, want ErrMalformedRecord", err)
	}
}

func TestValidateRecordRejectsWrongServiceFromDisk(t *testing.T) {
	dir := t.TempDir()
	svcDir := NewServiceDir(dir, "keymanager")
	rec := testRecord("keymanager")
	if _, err := Publish(svcDir, rec); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	_, err := ValidateRecord(svcDir, "boot-abc", os.Getpid(), "trust")
	if !errors.Is(err, ErrWrongService) {
		t.Errorf("ValidateRecord err = %v, want ErrWrongService", err)
	}
}
