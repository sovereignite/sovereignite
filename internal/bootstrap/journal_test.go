// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package bootstrap

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestFileJournalStoreAtomicallyPersistsVersionedRevisions(t *testing.T) {
	t.Parallel()

	directory := secureTempDir(t)
	path := filepath.Join(directory, "journal.json")
	store, err := NewFileJournalStore(path)
	if err != nil {
		t.Fatal(err)
	}
	journal := initialTestJournal(validTestConfiguration())
	if err := store.Save(0, journal); err != nil {
		t.Fatal(err)
	}
	next := cloneJournal(journal)
	next.Revision = 2
	next.UpdatedAt = next.UpdatedAt.Add(time.Second)
	next.Current = &Attempt{
		Step:      StepTPMKeyManagerCASigning,
		StartedAt: next.UpdatedAt,
		Attempts:  1,
	}
	if err := store.Save(1, next); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Revision != 2 ||
		loaded.Current == nil ||
		loaded.Current.Step != StepTPMKeyManagerCASigning {
		t.Fatalf("loaded journal = %#v", loaded)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("journal permissions = %04o, want 0600", info.Mode().Perm())
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	if len(entries) != 2 ||
		!slices.Contains(names, "journal.json") ||
		!slices.Contains(names, "journal.json.lock") {
		t.Fatalf("journal directory entries = %v, want journal and lock", entries)
	}
}

func TestFileJournalStoreRejectsStaleWriter(t *testing.T) {
	t.Parallel()

	path := filepath.Join(secureTempDir(t), "journal.json")
	first, err := NewFileJournalStore(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewFileJournalStore(path)
	if err != nil {
		t.Fatal(err)
	}
	journal := initialTestJournal(validTestConfiguration())
	if err := first.Save(0, journal); err != nil {
		t.Fatal(err)
	}
	if err := second.Save(0, journal); !errors.Is(err, ErrJournalConflict) {
		t.Fatalf("stale save error = %v, want revision conflict", err)
	}
}

func TestFileJournalStoreSerializesConcurrentWriters(t *testing.T) {
	t.Parallel()

	path := filepath.Join(secureTempDir(t), "journal.json")
	first, err := NewFileJournalStore(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewFileJournalStore(path)
	if err != nil {
		t.Fatal(err)
	}
	journal := initialTestJournal(validTestConfiguration())
	if err := first.Save(0, journal); err != nil {
		t.Fatal(err)
	}
	next := cloneJournal(journal)
	next.Revision = 2
	next.UpdatedAt = next.UpdatedAt.Add(time.Second)

	start := make(chan struct{})
	results := make(chan error, 2)
	for _, store := range []*FileJournalStore{first, second} {
		store := store
		go func() {
			<-start
			results <- store.Save(1, next)
		}()
	}
	close(start)
	successes := 0
	conflicts := 0
	for range 2 {
		err := <-results
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrJournalConflict):
			conflicts++
		default:
			t.Fatalf("concurrent Save() error = %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf(
			"concurrent results: successes=%d conflicts=%d, want one each",
			successes,
			conflicts,
		)
	}
}

func TestFileJournalStoreRejectsUnknownVersionFieldsAndTrailingData(t *testing.T) {
	t.Parallel()

	base, err := json.Marshal(initialTestJournal(validTestConfiguration()))
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(base, &object); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "unknown version",
			data: func() []byte {
				copyObject := cloneJSONMap(object)
				copyObject["version"] = float64(JournalVersion + 1)
				encoded, marshalErr := json.Marshal(copyObject)
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				return encoded
			}(),
		},
		{
			name: "unknown field",
			data: func() []byte {
				copyObject := cloneJSONMap(object)
				copyObject["private_key"] = "must not be accepted"
				encoded, marshalErr := json.Marshal(copyObject)
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				return encoded
			}(),
		},
		{
			name: "trailing JSON",
			data: append(append([]byte{}, base...), []byte("\n{}\n")...),
		},
		{
			name: "truncated",
			data: base[:len(base)/2],
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(secureTempDir(t), "journal.json")
			if err := os.WriteFile(path, test.data, 0o600); err != nil {
				t.Fatal(err)
			}
			store, err := NewFileJournalStore(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.Load(); err == nil {
				t.Fatal("Load() accepted invalid journal")
			}
		})
	}
}

func TestFileJournalStoreRejectsSymlinksAndPermissiveState(t *testing.T) {
	t.Parallel()

	t.Run("journal symlink", func(t *testing.T) {
		t.Parallel()
		directory := secureTempDir(t)
		target := filepath.Join(directory, "target.json")
		if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(directory, "journal.json")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		store, err := NewFileJournalStore(link)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Load(); err == nil {
			t.Fatal("Load() followed journal symlink")
		}
	})
	t.Run("lock symlink", func(t *testing.T) {
		t.Parallel()
		directory := secureTempDir(t)
		target := filepath.Join(directory, "target.lock")
		if err := os.WriteFile(target, []byte{}, 0o600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, "journal.json")
		if err := os.Symlink(target, path+".lock"); err != nil {
			t.Fatal(err)
		}
		store, err := NewFileJournalStore(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Save(
			0,
			initialTestJournal(validTestConfiguration()),
		); err == nil {
			t.Fatal("Save() followed journal lock symlink")
		}
	})
	t.Run("parent symlink", func(t *testing.T) {
		t.Parallel()
		root := secureTempDir(t)
		realDirectory := filepath.Join(root, "real")
		if err := os.Mkdir(realDirectory, 0o700); err != nil {
			t.Fatal(err)
		}
		linkDirectory := filepath.Join(root, "link")
		if err := os.Symlink(realDirectory, linkDirectory); err != nil {
			t.Fatal(err)
		}
		store, err := NewFileJournalStore(
			filepath.Join(linkDirectory, "journal.json"),
		)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Save(
			0,
			initialTestJournal(validTestConfiguration()),
		); err == nil {
			t.Fatal("Save() followed parent-directory symlink")
		}
	})
	t.Run("permissive parent", func(t *testing.T) {
		t.Parallel()
		root := secureTempDir(t)
		directory := filepath.Join(root, "state")
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, 0o755); err != nil {
			t.Fatal(err)
		}
		store, err := NewFileJournalStore(
			filepath.Join(directory, "journal.json"),
		)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Load(); err == nil {
			t.Fatal("Load() accepted permissive parent directory")
		}
	})
	t.Run("missing parent is not created", func(t *testing.T) {
		t.Parallel()
		root := secureTempDir(t)
		directory := filepath.Join(root, "not-provisioned")
		store, err := NewFileJournalStore(
			filepath.Join(directory, "journal.json"),
		)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Save(
			0,
			initialTestJournal(validTestConfiguration()),
		); err == nil {
			t.Fatal("Save() created an unprovisioned state directory")
		}
		if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("state directory stat error = %v, want not-exist", err)
		}
	})
	t.Run("permissive journal", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(secureTempDir(t), "journal.json")
		encoded, err := json.Marshal(initialTestJournal(validTestConfiguration()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		store, err := NewFileJournalStore(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Load(); err == nil {
			t.Fatal("Load() accepted permissive journal")
		}
	})
}

func TestJournalNeverPersistsArtifactOrSecretCanaryBytes(t *testing.T) {
	t.Parallel()

	config := validTestConfiguration()
	canary := "CLUSTER-SECRET-CANARY-DO-NOT-PERSIST"
	config.Authority.KubernetesTopology = testArtifact(
		ArtifactTopologyContract,
		"decision-006-r1",
		"authorized public topology references "+canary+"\n",
	)
	directory := secureTempDir(t)
	path := filepath.Join(directory, "journal.json")
	store, err := NewFileJournalStore(path)
	if err != nil {
		t.Fatal(err)
	}
	environment := newFakeUpstreams(config)
	coordinator := newTestCoordinator(
		t,
		config,
		store,
		environment,
		&fakePreparedPublisher{},
		coordinatorHooks{},
	)
	if err := coordinator.StartBootstrap(t.Context()); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(content, []byte(canary)) {
		t.Fatal("journal persisted authority artifact contents")
	}
	for _, artifactContent := range [][]byte{
		config.Artifacts.CARequest.Content,
		config.Artifacts.ControlPlane.Content,
		config.Artifacts.Dex.Content,
	} {
		if bytes.Contains(content, bytes.TrimSpace(artifactContent)) {
			t.Fatal("journal persisted rendered artifact contents")
		}
	}
	if strings.Contains(string(content), "PRIVATE KEY") {
		t.Fatal("journal contains private key text")
	}
}

func TestValidateJournalRejectsEarlyOrPartialCompletion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Journal)
	}{
		{
			name: "complete before nine steps",
			mutate: func(journal *Journal) {
				journal.State = JournalComplete
			},
		},
		{
			name: "prepared before step five",
			mutate: func(journal *Journal) {
				journal.Prepared = true
				preparedAt := journal.UpdatedAt
				journal.PreparedAt = &preparedAt
			},
		},
		{
			name: "unknown current step",
			mutate: func(journal *Journal) {
				journal.Current = &Attempt{
					Step:      "rendered manifests complete",
					StartedAt: journal.UpdatedAt,
					Attempts:  1,
				}
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			journal := initialTestJournal(validTestConfiguration())
			test.mutate(&journal)
			if err := validateJournal(journal); err == nil {
				t.Fatal("invalid journal unexpectedly validated")
			}
		})
	}
}

func cloneJSONMap(source map[string]any) map[string]any {
	clone := make(map[string]any, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}
