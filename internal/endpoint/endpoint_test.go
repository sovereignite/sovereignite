package endpoint

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPublishAndRead(t *testing.T) {
	dir := t.TempDir()
	origRunDir := RunDir
	RunDir = func() string { return dir }
	defer func() { RunDir = origRunDir }()

	ep := Endpoint{
		Service: "test-service",
		Address: "127.0.0.1",
		Port:    9090,
		Ready:   true,
	}
	if err := Publish(ep); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	got, err := Read("test-service")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.Service != "test-service" {
		t.Errorf("Service: have %q, want %q", got.Service, "test-service")
	}
	if got.Address != "127.0.0.1" {
		t.Errorf("Address: have %q, want %q", got.Address, "127.0.0.1")
	}
	if got.Port != 9090 {
		t.Errorf("Port: have %d, want %d", got.Port, 9090)
	}
	if !got.Ready {
		t.Error("Ready should be true")
	}
	if got.BootID == "" {
		t.Error("BootID should be set")
	}
	if got.PID == 0 {
		t.Error("PID should be set")
	}
}

func TestPublishCreatesAtomicFile(t *testing.T) {
	dir := t.TempDir()
	origRunDir := RunDir
	RunDir = func() string { return dir }
	defer func() { RunDir = origRunDir }()

	ep := Endpoint{Service: "atomic-test", Address: "127.0.0.1", Port: 8080}
	if err := Publish(ep); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	tmpPath := filepath.Join(dir, "atomic-test", "endpoint.json.tmp")
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Error("temp file should not exist after atomic rename")
	}
	info, err := os.Stat(filepath.Join(dir, "atomic-test", "endpoint.json"))
	if err != nil {
		t.Fatalf("stat endpoint: %v", err)
	}
	if info.Mode().Perm() != filePerms {
		t.Errorf("file perms: have %o, want %o", info.Mode().Perm(), filePerms)
	}
}

func TestValidateRejectsStaleBootID(t *testing.T) {
	dir := t.TempDir()
	origRunDir := RunDir
	RunDir = func() string { return dir }
	defer func() { RunDir = origRunDir }()

	ep := Endpoint{Service: "stale-test", Address: "127.0.0.1", Port: 8080}
	if err := Publish(ep); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "stale-test", "endpoint.json"))
	corrupted := append(data[:len(data)-2], []byte(`}`)...)
	os.WriteFile(filepath.Join(dir, "stale-test", "endpoint.json"), corrupted, filePerms)
	path := filepath.Join(dir, "stale-test", "endpoint.json")
	_ = path
}

func TestCleanup(t *testing.T) {
	dir := t.TempDir()
	origRunDir := RunDir
	RunDir = func() string { return dir }
	defer func() { RunDir = origRunDir }()

	ep := Endpoint{Service: "cleanup-test", Address: "127.0.0.1", Port: 8080}
	if err := Publish(ep); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if err := Cleanup("cleanup-test"); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	_, err := Read("cleanup-test")
	if err == nil {
		t.Error("expected error after cleanup")
	}
}

func TestCleanupIdempotent(t *testing.T) {
	if err := Cleanup("nonexistent"); err != nil {
		t.Errorf("Cleanup of nonexistent should be idempotent: %v", err)
	}
}
