// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package sovereignitev1

import (
	"bytes"
	"crypto/sha256"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	protocVersion          = "34.1"
	protocGenGoVersion     = "v1.36.11"
	protocGenGoGrpcVersion = "v1.6.2"
	modulePath             = "github.com/sovereignite/sovereignite"
	protoSource            = "pkg/api/proto/sovereignite/v1/sovereignite.proto"
	protoSHA256            = "677689d31614d760969321a4b6b723b73f1587d9f0bbc8ae9b764fa0bdfb4355"
)

func requireProtoc(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("protoc"); err != nil {
		t.Fatalf("protoc not found in PATH: %v", err)
	}
}

func TestProtoToolchainVersions(t *testing.T) {
	requireProtoc(t)

	out, err := exec.Command("protoc", "--version").CombinedOutput()
	if err != nil {
		t.Fatalf("protoc --version failed: %v\n%s", err, out)
	}
	got := strings.TrimSpace(string(out))
	if !strings.Contains(got, protocVersion) {
		t.Errorf("protoc version mismatch: want %s, got %s", protocVersion, got)
	}
}

func TestProtoSourceChecksum(t *testing.T) {
	repoRoot := findRepoRoot(t)
	protoFile := filepath.Join(repoRoot, protoSource)

	data, err := os.ReadFile(protoFile)
	if err != nil {
		t.Fatalf("failed to read proto source: %v", err)
	}

	hash := sha256.Sum256(data)
	got := hex(hash[:])
	if got != protoSHA256 {
		t.Errorf("sovereignite.proto checksum mismatch: want %s, got %s", protoSHA256, got)
	}
}

func TestProtoGenerationReproducible(t *testing.T) {
	requireProtoc(t)

	repoRoot := findRepoRoot(t)

	committedDir := filepath.Join(repoRoot, "pkg", "api", "proto", "sovereignite", "v1")
	tmpDir := t.TempDir()
	tmpOut := filepath.Join(tmpDir, "out")
	if err := os.MkdirAll(tmpOut, 0o755); err != nil {
		t.Fatal(err)
	}

	generateProto(t, repoRoot, tmpOut)

	protoFiles := []string{
		"sovereignite.pb.go",
		"sovereignite_grpc.pb.go",
	}

	for _, name := range protoFiles {
		committed := filepath.Join(committedDir, name)
		generated := filepath.Join(tmpOut, "pkg", "api", "proto", "sovereignite", "v1", name)

		if _, err := os.Stat(generated); os.IsNotExist(err) {
			t.Errorf("generated file %s does not exist", name)
			continue
		}

		committedContent, err := os.ReadFile(committed)
		if err != nil {
			t.Fatalf("failed to read committed file %s: %v", committed, err)
		}

		generatedContent, err := os.ReadFile(generated)
		if err != nil {
			t.Fatalf("failed to read generated file %s: %v", generated, err)
		}

		committedHash := sha256.Sum256(committedContent)
		generatedHash := sha256.Sum256(generatedContent)

		if !bytes.Equal(committedHash[:], generatedHash[:]) {
			diffFile := filepath.Join(tmpDir, name+".diff")
			diffCmd := exec.Command("diff", "-u", committed, generated)
			diffOut, _ := diffCmd.CombinedOutput()
			_ = os.WriteFile(diffFile, diffOut, 0o644)

			t.Errorf(
				"generated %s differs from committed (committed=%x generated=%x diff=%s)",
				name, committedHash, generatedHash, diffFile,
			)
		} else {
			t.Logf("OK: %s matches (sha256=%x)", name, committedHash)
		}
	}
}

func TestProtoGenerationDeterministic(t *testing.T) {
	requireProtoc(t)

	repoRoot := findRepoRoot(t)

	dir1 := t.TempDir()
	out1 := filepath.Join(dir1, "out")
	if err := os.MkdirAll(out1, 0o755); err != nil {
		t.Fatal(err)
	}
	generateProto(t, repoRoot, out1)

	dir2 := t.TempDir()
	out2 := filepath.Join(dir2, "out")
	if err := os.MkdirAll(out2, 0o755); err != nil {
		t.Fatal(err)
	}
	generateProto(t, repoRoot, out2)

	protoFiles := []string{
		"sovereignite.pb.go",
		"sovereignite_grpc.pb.go",
	}

	for _, name := range protoFiles {
		f1 := filepath.Join(out1, "pkg", "api", "proto", "sovereignite", "v1", name)
		f2 := filepath.Join(out2, "pkg", "api", "proto", "sovereignite", "v1", name)

		c1, err := os.ReadFile(f1)
		if err != nil {
			t.Fatalf("read first generation %s: %v", name, err)
		}
		c2, err := os.ReadFile(f2)
		if err != nil {
			t.Fatalf("read second generation %s: %v", name, err)
		}

		h1 := sha256.Sum256(c1)
		h2 := sha256.Sum256(c2)

		if !bytes.Equal(h1[:], h2[:]) {
			t.Errorf("non-deterministic generation: %s first=%x second=%x", name, h1, h2)
		} else {
			t.Logf("OK: %s deterministic (sha256=%x)", name, h1)
		}
	}
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repository root (no go.mod found)")
		}
		dir = parent
	}
}

func generateProto(t *testing.T, repoRoot, outDir string) {
	t.Helper()

	protoFile := filepath.Join(repoRoot, protoSource)
	if _, err := os.Stat(protoFile); os.IsNotExist(err) {
		t.Fatalf("proto source not found: %s", protoFile)
	}

	args := []string{
		"--proto_path=" + repoRoot,
		"--go_out=" + outDir,
		"--go_opt=module=" + modulePath,
		"--go-grpc_out=" + outDir,
		"--go-grpc_opt=module=" + modulePath,
		protoFile,
	}

	cmd := exec.Command("protoc", args...)
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(), "PATH="+os.Getenv("PATH"))

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("protoc generation failed: %v\n%s", err, out)
	}
	t.Logf("protoc output: %s", strings.TrimSpace(string(out)))
}

func hex(b []byte) string {
	const hexDigits = "0123456789abcdef"
	buf := make([]byte, len(b)*2)
	for i, v := range b {
		buf[i*2] = hexDigits[v>>4]
		buf[i*2+1] = hexDigits[v&0x0f]
	}
	return string(buf)
}
