// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestStepsAreExactlyTheNineV5Steps(t *testing.T) {
	t.Parallel()

	want := []Step{
		"TPM-keymanager CA signing",
		"kubelet config",
		"Calico IPv6 using injected ULA",
		"Istio ingress",
		"SPIRE TPM plugin/TPM Device Key config",
		"initialize Kubernetes API server",
		"wait control plane",
		"apply cluster configs",
		"mark complete",
	}
	got := Steps()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Steps() = %#v, want %#v", got, want)
	}
	got[0] = StepMarkComplete
	if Steps()[0] != StepTPMKeyManagerCASigning {
		t.Fatal("mutating returned steps changed the closed step table")
	}
}

func TestPreparedIsDistinctFromComplete(t *testing.T) {
	t.Parallel()

	config := validTestConfiguration()
	store, err := NewFileJournalStore(
		filepath.Join(secureTempDir(t), "journal.json"),
	)
	if err != nil {
		t.Fatal(err)
	}
	environment := newFakeUpstreams(config)
	prepared := &fakePreparedPublisher{}
	crash := errors.New("simulated crash after prepared commit")
	coordinator := newTestCoordinator(
		t,
		config,
		store,
		environment,
		prepared,
		coordinatorHooks{
			afterCommit: func(step Step) error {
				if step == StepSPIRETPMConfig {
					return crash
				}
				return nil
			},
		},
	)
	if err := coordinator.StartBootstrap(context.Background()); !errors.Is(err, crash) {
		t.Fatalf("StartBootstrap() error = %v, want simulated crash", err)
	}
	journal, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !journal.Prepared || len(journal.Steps) != 5 {
		t.Fatalf(
			"journal prepared=%t steps=%d, want true and 5",
			journal.Prepared,
			len(journal.Steps),
		)
	}
	if journal.State == JournalComplete {
		t.Fatal("prepared journal was marked complete")
	}
	publishCalls, _ := prepared.counts()
	if publishCalls != 0 {
		t.Fatalf("prepared publish calls = %d, want none before crash", publishCalls)
	}
	status, err := coordinator.GetStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.State != StatusInProgress ||
		status.CurrentStep != StepInitializeAPIServer {
		t.Fatalf("prepared status = %#v, want in-progress step 6", status)
	}

	resumed := newTestCoordinator(
		t,
		config,
		store,
		environment,
		prepared,
		coordinatorHooks{},
	)
	if err := resumed.StartBootstrap(context.Background()); err != nil {
		t.Fatalf("resume bootstrap: %v", err)
	}
	publishCalls, verifyCalls := prepared.counts()
	if publishCalls == 0 || verifyCalls == 0 {
		t.Fatalf(
			"prepared publisher calls = publish %d verify %d, want both",
			publishCalls,
			verifyCalls,
		)
	}
	status, err = resumed.GetStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.State != StatusComplete || status.CurrentStep != StepMarkComplete {
		t.Fatalf("complete status = %#v", status)
	}
}

func TestPreparedPublicationFailureResumesWithoutRepeatingStepFive(t *testing.T) {
	t.Parallel()

	config := validTestConfiguration()
	store, err := NewFileJournalStore(
		filepath.Join(secureTempDir(t), "journal.json"),
	)
	if err != nil {
		t.Fatal(err)
	}
	environment := newFakeUpstreams(config)
	prepared := &fakePreparedPublisher{
		publishErr: errors.New("runtime directory unavailable"),
	}
	coordinator := newTestCoordinator(
		t,
		config,
		store,
		environment,
		prepared,
		coordinatorHooks{},
	)
	if err := coordinator.StartBootstrap(context.Background()); err == nil {
		t.Fatal("prepared publication failure unexpectedly succeeded")
	}
	journal, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !journal.Prepared ||
		len(journal.Steps) != stepIndex(StepSPIRETPMConfig)+1 ||
		journal.Failure == nil ||
		journal.Failure.Code != failurePrepared {
		t.Fatalf("prepared failure journal = %#v", journal)
	}
	before := actionCalls(environment)["spire-tpm"]
	prepared.mu.Lock()
	prepared.publishErr = nil
	prepared.mu.Unlock()
	if err := coordinator.StartBootstrap(context.Background()); err != nil {
		t.Fatalf("retry prepared publication: %v", err)
	}
	after := actionCalls(environment)["spire-tpm"]
	if after != before {
		t.Fatalf("SPIRE prepare calls = %d after retry, want %d", after, before)
	}
}

func TestCrashAfterActionResumesEveryStepWithoutRecreation(t *testing.T) {
	for targetIndex, target := range Steps() {
		targetIndex := targetIndex
		target := target
		t.Run(string(target), func(t *testing.T) {
			config := validTestConfiguration()
			store, err := NewFileJournalStore(
				filepath.Join(secureTempDir(t), "journal.json"),
			)
			if err != nil {
				t.Fatal(err)
			}
			environment := newFakeUpstreams(config)
			prepared := &fakePreparedPublisher{}
			crash := errors.New("simulated post-action crash")
			crashed := false
			coordinator := newTestCoordinator(
				t,
				config,
				store,
				environment,
				prepared,
				coordinatorHooks{
					afterAction: func(step Step) error {
						if step == target && !crashed {
							crashed = true
							return crash
						}
						return nil
					},
				},
			)
			if err := coordinator.StartBootstrap(context.Background()); !errors.Is(err, crash) {
				t.Fatalf("StartBootstrap() error = %v, want crash", err)
			}
			journal, err := store.Load()
			if err != nil {
				t.Fatal(err)
			}
			if len(journal.Steps) != targetIndex {
				t.Fatalf(
					"completed steps = %d, want %d",
					len(journal.Steps),
					targetIndex,
				)
			}
			if journal.Current == nil || journal.Current.Step != target {
				t.Fatalf("current attempt = %#v, want %q", journal.Current, target)
			}
			if targetIndex < stepIndex(StepSPIRETPMConfig)+1 &&
				journal.Prepared {
				t.Fatal("journal became prepared before step 5 committed")
			}

			resumed := newTestCoordinator(
				t,
				config,
				store,
				environment,
				prepared,
				coordinatorHooks{},
			)
			if err := resumed.StartBootstrap(context.Background()); err != nil {
				t.Fatalf("resume bootstrap: %v", err)
			}
			assertAllCreationsAtMostOnce(t, environment)
			completed, err := store.Load()
			if err != nil {
				t.Fatal(err)
			}
			if completed.State != JournalComplete ||
				len(completed.Steps) != len(Steps()) {
				t.Fatalf("resumed journal = %#v", completed)
			}
		})
	}
}

func TestCrashAfterIntentResumesEveryStepWithoutEarlySideEffects(t *testing.T) {
	for targetIndex, target := range Steps() {
		targetIndex := targetIndex
		target := target
		t.Run(string(target), func(t *testing.T) {
			config := validTestConfiguration()
			store, err := NewFileJournalStore(
				filepath.Join(secureTempDir(t), "journal.json"),
			)
			if err != nil {
				t.Fatal(err)
			}
			environment := newFakeUpstreams(config)
			prepared := &fakePreparedPublisher{}
			crash := errors.New("simulated post-intent crash")
			coordinator := newTestCoordinator(
				t,
				config,
				store,
				environment,
				prepared,
				coordinatorHooks{
					afterIntent: func(step Step) error {
						if step == target {
							return crash
						}
						return nil
					},
				},
			)
			if err := coordinator.StartBootstrap(context.Background()); !errors.Is(err, crash) {
				t.Fatalf("StartBootstrap() error = %v, want crash", err)
			}
			journal, err := store.Load()
			if err != nil {
				t.Fatal(err)
			}
			if len(journal.Steps) != targetIndex ||
				journal.Current == nil ||
				journal.Current.Step != target {
				t.Fatalf("post-intent journal = %#v", journal)
			}
			targetActionCount := actionCountForStep(environment, target)
			if targetActionCount != 0 {
				t.Fatalf(
					"target step %q action count = %d before action, want 0",
					target,
					targetActionCount,
				)
			}

			resumed := newTestCoordinator(
				t,
				config,
				store,
				environment,
				prepared,
				coordinatorHooks{},
			)
			if err := resumed.StartBootstrap(context.Background()); err != nil {
				t.Fatalf("resume bootstrap: %v", err)
			}
			assertAllCreationsAtMostOnce(t, environment)
		})
	}
}

func TestCrashAfterCommitResumesEveryStep(t *testing.T) {
	for targetIndex, target := range Steps() {
		targetIndex := targetIndex
		target := target
		t.Run(string(target), func(t *testing.T) {
			config := validTestConfiguration()
			store, err := NewFileJournalStore(
				filepath.Join(secureTempDir(t), "journal.json"),
			)
			if err != nil {
				t.Fatal(err)
			}
			environment := newFakeUpstreams(config)
			prepared := &fakePreparedPublisher{}
			crash := errors.New("simulated post-commit crash")
			crashed := false
			coordinator := newTestCoordinator(
				t,
				config,
				store,
				environment,
				prepared,
				coordinatorHooks{
					afterCommit: func(step Step) error {
						if step == target && !crashed {
							crashed = true
							return crash
						}
						return nil
					},
				},
			)
			if err := coordinator.StartBootstrap(context.Background()); !errors.Is(err, crash) {
				t.Fatalf("StartBootstrap() error = %v, want crash", err)
			}
			journal, err := store.Load()
			if err != nil {
				t.Fatal(err)
			}
			if len(journal.Steps) != targetIndex+1 {
				t.Fatalf(
					"completed steps = %d, want %d",
					len(journal.Steps),
					targetIndex+1,
				)
			}
			if target == StepSPIRETPMConfig && !journal.Prepared {
				t.Fatal("step 5 commit did not durably record prepared")
			}
			if target == StepMarkComplete && journal.State != JournalComplete {
				t.Fatal("step 9 commit did not durably record complete")
			}

			resumed := newTestCoordinator(
				t,
				config,
				store,
				environment,
				prepared,
				coordinatorHooks{},
			)
			if err := resumed.StartBootstrap(context.Background()); err != nil {
				t.Fatalf("resume bootstrap: %v", err)
			}
			assertAllCreationsAtMostOnce(t, environment)
		})
	}
}

func TestCompletedRetryVerifiesWithoutExecutingOrRecreating(t *testing.T) {
	t.Parallel()

	config := validTestConfiguration()
	store, err := NewFileJournalStore(
		filepath.Join(secureTempDir(t), "journal.json"),
	)
	if err != nil {
		t.Fatal(err)
	}
	environment := newFakeUpstreams(config)
	prepared := &fakePreparedPublisher{}
	coordinator := newTestCoordinator(
		t,
		config,
		store,
		environment,
		prepared,
		coordinatorHooks{},
	)
	if err := coordinator.StartBootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	beforeActions := actionCalls(environment)
	beforeCreations := resourceCreations(environment)
	if err := coordinator.StartBootstrap(context.Background()); err != nil {
		t.Fatalf("retry complete bootstrap: %v", err)
	}
	if got := actionCalls(environment); !reflect.DeepEqual(got, beforeActions) {
		t.Fatalf("completed retry action calls = %#v, want %#v", got, beforeActions)
	}
	if got := resourceCreations(environment); !reflect.DeepEqual(got, beforeCreations) {
		t.Fatalf("completed retry creations = %#v, want %#v", got, beforeCreations)
	}
}

func TestResumeRejectsChangedValidatedConfiguration(t *testing.T) {
	t.Parallel()

	config := validTestConfiguration()
	store, err := NewFileJournalStore(
		filepath.Join(secureTempDir(t), "journal.json"),
	)
	if err != nil {
		t.Fatal(err)
	}
	environment := newFakeUpstreams(config)
	prepared := &fakePreparedPublisher{}
	crash := errors.New("stop after first commit")
	coordinator := newTestCoordinator(
		t,
		config,
		store,
		environment,
		prepared,
		coordinatorHooks{
			afterCommit: func(step Step) error {
				if step == StepTPMKeyManagerCASigning {
					return crash
				}
				return nil
			},
		},
	)
	if err := coordinator.StartBootstrap(context.Background()); !errors.Is(err, crash) {
		t.Fatalf("StartBootstrap() error = %v, want crash", err)
	}
	before := actionCalls(environment)

	changed := validTestConfiguration()
	changed.Authority.KubernetesTopology = testArtifact(
		ArtifactTopologyContract,
		"decision-006-r2",
		"different complete topology\n",
	)
	changedEnvironment := newFakeUpstreams(changed)
	resumed := newTestCoordinator(
		t,
		changed,
		store,
		changedEnvironment,
		prepared,
		coordinatorHooks{},
	)
	err = resumed.StartBootstrap(context.Background())
	if !errors.Is(err, ErrIncompatibleConfiguration) {
		t.Fatalf("resume error = %v, want incompatible configuration", err)
	}
	if got := actionCalls(environment); !reflect.DeepEqual(got, before) {
		t.Fatalf("original actions changed: got %#v want %#v", got, before)
	}
	if got := actionCalls(changedEnvironment); len(got) != 0 {
		t.Fatalf("changed configuration executed actions: %#v", got)
	}
}

func TestCompletedVerificationFailurePreservesResourcesAndClearsComplete(t *testing.T) {
	t.Parallel()

	config := validTestConfiguration()
	store, err := NewFileJournalStore(
		filepath.Join(secureTempDir(t), "journal.json"),
	)
	if err != nil {
		t.Fatal(err)
	}
	environment := newFakeUpstreams(config)
	prepared := &fakePreparedPublisher{}
	coordinator := newTestCoordinator(
		t,
		config,
		store,
		environment,
		prepared,
		coordinatorHooks{},
	)
	if err := coordinator.StartBootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := resourceCreations(environment)
	setVerificationFailure(
		environment,
		"ca-signing",
		errors.New("public CA fingerprint changed"),
	)
	err = coordinator.StartBootstrap(context.Background())
	if err == nil {
		t.Fatal("completed verification unexpectedly succeeded")
	}
	if got := resourceCreations(environment); !reflect.DeepEqual(got, before) {
		t.Fatalf("verification failure recreated resources: %#v", got)
	}
	journal, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if journal.State != JournalFailed ||
		journal.Failure == nil ||
		journal.Failure.Step != StepTPMKeyManagerCASigning ||
		len(journal.Steps) != len(Steps()) {
		t.Fatalf("failed verification journal = %#v", journal)
	}
	status, err := coordinator.GetStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.State != StatusFailed ||
		status.CurrentStep != StepTPMKeyManagerCASigning {
		t.Fatalf("verification-failure status = %#v", status)
	}
}

func TestPartialApplyRetryDoesNotRecreateResources(t *testing.T) {
	t.Parallel()

	config := validTestConfiguration()
	store, err := NewFileJournalStore(
		filepath.Join(secureTempDir(t), "journal.json"),
	)
	if err != nil {
		t.Fatal(err)
	}
	environment := newFakeUpstreams(config)
	setFailOnce(
		environment,
		"dex-reconcile",
		errors.New("Dex controller is not ready"),
	)
	prepared := &fakePreparedPublisher{}
	coordinator := newTestCoordinator(
		t,
		config,
		store,
		environment,
		prepared,
		coordinatorHooks{},
	)
	if err := coordinator.StartBootstrap(context.Background()); err == nil {
		t.Fatal("partial apply unexpectedly succeeded")
	}
	journal, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if journal.State != JournalFailed ||
		len(journal.Steps) != stepIndex(StepApplyClusterConfigs) {
		t.Fatalf("partial apply journal = %#v", journal)
	}
	if err := coordinator.StartBootstrap(context.Background()); err != nil {
		t.Fatalf("retry partial apply: %v", err)
	}
	assertAllCreationsAtMostOnce(t, environment)
}

func TestAdapterErrorDetailsAreNotPersistedOrReportedInStatus(t *testing.T) {
	t.Parallel()

	config := validTestConfiguration()
	path := filepath.Join(secureTempDir(t), "journal.json")
	store, err := NewFileJournalStore(path)
	if err != nil {
		t.Fatal(err)
	}
	environment := newFakeUpstreams(config)
	const canary = "PRIVATE-KEY-CANARY-FROM-UPSTREAM"
	setFailOnce(environment, "ca-signing", errors.New(canary))
	coordinator := newTestCoordinator(
		t,
		config,
		store,
		environment,
		&fakePreparedPublisher{},
		coordinatorHooks{},
	)
	if err := coordinator.StartBootstrap(context.Background()); err == nil {
		t.Fatal("upstream failure unexpectedly succeeded")
	}
	journal, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	encodedFailure := journal.Failure.Message + journal.Failure.Code
	if strings.Contains(encodedFailure, canary) {
		t.Fatal("journal failure contains upstream canary")
	}
	status, err := coordinator.GetStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(status.Message, canary) {
		t.Fatal("GetStatus message contains upstream canary")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(content, []byte(canary)) {
		t.Fatal("journal file contains upstream canary")
	}
}

func TestStepNineReverifiesAllPriorResults(t *testing.T) {
	t.Parallel()

	config := validTestConfiguration()
	store, err := NewFileJournalStore(
		filepath.Join(secureTempDir(t), "journal.json"),
	)
	if err != nil {
		t.Fatal(err)
	}
	environment := newFakeUpstreams(config)
	prepared := &fakePreparedPublisher{}
	crash := errors.New("stop before completion commit")
	coordinator := newTestCoordinator(
		t,
		config,
		store,
		environment,
		prepared,
		coordinatorHooks{
			afterAction: func(step Step) error {
				if step == StepMarkComplete {
					return crash
				}
				return nil
			},
		},
	)
	if err := coordinator.StartBootstrap(context.Background()); !errors.Is(err, crash) {
		t.Fatalf("StartBootstrap() error = %v, want crash", err)
	}
	environment.mu.Lock()
	caVerifications := environment.verifyCalls["ca-signing"]
	reconcileVerifications := environment.verifyCalls["kubernetes-reconcile"]
	environment.mu.Unlock()
	if caVerifications < 2 || reconcileVerifications < 2 {
		t.Fatalf(
			"step 9 verification counts: CA=%d Kubernetes reconcile=%d, want at least 2",
			caVerifications,
			reconcileVerifications,
		)
	}
}

func TestExpectedStepInventoryHasNoExtraComponents(t *testing.T) {
	t.Parallel()

	for _, step := range Steps() {
		components := expectedComponents(step)
		if len(components) == 0 {
			t.Fatalf("step %q has no expected component", step)
		}
		if slices.Contains(components, Component("sovereignite-crd")) {
			t.Fatalf("step %q contains an invented component", step)
		}
	}
}

func actionCountForStep(environment *fakeUpstreams, step Step) int {
	actions := actionCalls(environment)
	switch step {
	case StepTPMKeyManagerCASigning:
		return actions["ca-signing"]
	case StepKubeletConfig:
		return actions["kubelet"]
	case StepCalicoIPv6:
		return actions["calico-ipv6"]
	case StepIstioIngress:
		return actions["istio-ingress"]
	case StepSPIRETPMConfig:
		return actions["spire-tpm"]
	case StepInitializeAPIServer:
		return actions["api-server"]
	case StepWaitControlPlane:
		return actions["control-plane"]
	case StepApplyClusterConfigs:
		return actions["kubernetes-reconcile"] +
			actions["calico-reconcile"] +
			actions["istio-reconcile"] +
			actions["spire-reconcile"] +
			actions["dex-reconcile"]
	case StepMarkComplete:
		return actions["kubernetes-ready"] +
			actions["calico-ready"] +
			actions["istio-ready"] +
			actions["spire-ready"] +
			actions["dex-ready"]
	default:
		return -1
	}
}

func TestStartBootstrapResumesSameTransaction(t *testing.T) {
	t.Parallel()

	config := validTestConfiguration()
	store, err := NewFileJournalStore(
		filepath.Join(secureTempDir(t), "journal.json"),
	)
	if err != nil {
		t.Fatal(err)
	}
	environment := newFakeUpstreams(config)
	prepared := &fakePreparedPublisher{}
	crash := errors.New("stop after first commit")
	coordinator := newTestCoordinator(
		t,
		config,
		store,
		environment,
		prepared,
		coordinatorHooks{
			afterCommit: func(step Step) error {
				if step == StepTPMKeyManagerCASigning {
					return crash
				}
				return nil
			},
		},
	)
	if err := coordinator.StartBootstrap(context.Background()); !errors.Is(err, crash) {
		t.Fatalf("StartBootstrap() error = %v, want crash", err)
	}
	snapshot, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	originalTransactionID := snapshot.TransactionID
	if originalTransactionID == "" {
		t.Fatal("initial journal has no transaction ID")
	}

	resumed := newTestCoordinator(
		t,
		config,
		store,
		environment,
		prepared,
		coordinatorHooks{},
	)
	if err := resumed.StartBootstrap(context.Background()); err != nil {
		t.Fatalf("resume: %v", err)
	}
	resumedJournal, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if resumedJournal.TransactionID != originalTransactionID {
		t.Fatalf(
			"transaction ID changed on resume: got %q, want %q",
			resumedJournal.TransactionID,
			originalTransactionID,
		)
	}
}

func TestGetStatusNeverCompletesEarly(t *testing.T) {
	t.Parallel()

	config := validTestConfiguration()
	store, err := NewFileJournalStore(
		filepath.Join(secureTempDir(t), "journal.json"),
	)
	if err != nil {
		t.Fatal(err)
	}
	environment := newFakeUpstreams(config)
	prepared := &fakePreparedPublisher{}
	crash := errors.New("stop before completion")
	crashed := false
	coordinator := newTestCoordinator(
		t,
		config,
		store,
		environment,
		prepared,
		coordinatorHooks{
			afterAction: func(step Step) error {
				if step == StepWaitControlPlane && !crashed {
					crashed = true
					return crash
				}
				return nil
			},
		},
	)
	if err := coordinator.StartBootstrap(context.Background()); !errors.Is(err, crash) {
		t.Fatalf("StartBootstrap() error = %v, want crash", err)
	}

	status, err := coordinator.GetStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.State == StatusComplete {
		t.Fatal("GetStatus reported complete before all nine steps were verified")
	}
	if status.State != StatusInProgress {
		t.Fatalf("GetStatus state = %q, want in_progress", status.State)
	}
	if status.CurrentStep != StepWaitControlPlane {
		t.Fatalf("GetStatus current step = %q, want %q", status.CurrentStep, StepWaitControlPlane)
	}

	resumed := newTestCoordinator(
		t,
		config,
		store,
		environment,
		prepared,
		coordinatorHooks{},
	)
	if err := resumed.StartBootstrap(context.Background()); err != nil {
		t.Fatalf("resume: %v", err)
	}
	completed, err := resumed.GetStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if completed.State != StatusComplete {
		t.Fatalf("final status = %q, want complete", completed.State)
	}
}

func TestEvidencePersistsAcrossRestart(t *testing.T) {
	t.Parallel()

	config := validTestConfiguration()
	store, err := NewFileJournalStore(
		filepath.Join(secureTempDir(t), "journal.json"),
	)
	if err != nil {
		t.Fatal(err)
	}
	environment := newFakeUpstreams(config)
	prepared := &fakePreparedPublisher{}
	crash := errors.New("stop after second commit")
	crashed := false
	coordinator := newTestCoordinator(
		t,
		config,
		store,
		environment,
		prepared,
		coordinatorHooks{
			afterCommit: func(step Step) error {
				if step == StepKubeletConfig && !crashed {
					crashed = true
					return crash
				}
				return nil
			},
		},
	)
	if err := coordinator.StartBootstrap(context.Background()); !errors.Is(err, crash) {
		t.Fatalf("StartBootstrap() error = %v, want crash", err)
	}
	snapshot, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Steps) != 2 {
		t.Fatalf("completed steps = %d, want 2", len(snapshot.Steps))
	}
	if snapshot.Steps[0].Step != StepTPMKeyManagerCASigning {
		t.Fatalf("step 1 = %q, want %q", snapshot.Steps[0].Step, StepTPMKeyManagerCASigning)
	}
	if snapshot.Steps[0].Evidence.Observations == nil {
		t.Fatal("step 1 evidence is nil")
	}
	if snapshot.Steps[0].CompletedAt.IsZero() {
		t.Fatal("step 1 completion time is zero")
	}
	if snapshot.Steps[1].Step != StepKubeletConfig {
		t.Fatalf("step 2 = %q, want %q", snapshot.Steps[1].Step, StepKubeletConfig)
	}

	resumed := newTestCoordinator(
		t,
		config,
		store,
		environment,
		prepared,
		coordinatorHooks{},
	)
	if err := resumed.StartBootstrap(context.Background()); err != nil {
		t.Fatalf("resume: %v", err)
	}
	reloaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.Steps) != len(Steps()) {
		t.Fatalf("reloaded steps = %d, want %d", len(reloaded.Steps), len(Steps()))
	}
	if reloaded.Steps[0].Step != StepTPMKeyManagerCASigning {
		t.Fatalf("step 1 = %q, want %q", reloaded.Steps[0].Step, StepTPMKeyManagerCASigning)
	}
	if reloaded.Steps[0].Evidence.Observations == nil {
		t.Fatal("step 1 evidence observations are nil after restart")
	}
	if reloaded.Steps[0].CompletedAt.IsZero() {
		t.Fatal("step 1 completion time is zero after restart")
	}
	if reloaded.Steps[1].Step != StepKubeletConfig {
		t.Fatalf("step 2 = %q, want %q", reloaded.Steps[1].Step, StepKubeletConfig)
	}
	if reloaded.Steps[1].Evidence.Observations == nil {
		t.Fatal("step 2 evidence observations are nil after restart")
	}
	if reloaded.Steps[1].CompletedAt.IsZero() {
		t.Fatal("step 2 completion time is zero after restart")
	}
}

func TestJournalVersionIsDurable(t *testing.T) {
	t.Parallel()

	config := validTestConfiguration()
	store, err := NewFileJournalStore(
		filepath.Join(secureTempDir(t), "journal.json"),
	)
	if err != nil {
		t.Fatal(err)
	}
	environment := newFakeUpstreams(config)
	prepared := &fakePreparedPublisher{}
	crash := errors.New("stop after first commit")
	coordinator := newTestCoordinator(
		t,
		config,
		store,
		environment,
		prepared,
		coordinatorHooks{
			afterCommit: func(step Step) error {
				if step == StepTPMKeyManagerCASigning {
					return crash
				}
				return nil
			},
		},
	)
	if err := coordinator.StartBootstrap(context.Background()); !errors.Is(err, crash) {
		t.Fatalf("StartBootstrap() error = %v, want crash", err)
	}
	snapshot, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Version != JournalVersion {
		t.Fatalf("journal version = %d, want %d", snapshot.Version, JournalVersion)
	}
	if snapshot.BootstrapVersion != config.BootstrapVersion {
		t.Fatalf(
			"bootstrap version = %q, want %q",
			snapshot.BootstrapVersion,
			config.BootstrapVersion,
		)
	}
	if snapshot.ConfigurationSHA256 == "" {
		t.Fatal("journal configuration digest is empty")
	}
}

func TestJournalFailureIsDurable(t *testing.T) {
	t.Parallel()

	config := validTestConfiguration()
	store, err := NewFileJournalStore(
		filepath.Join(secureTempDir(t), "journal.json"),
	)
	if err != nil {
		t.Fatal(err)
	}
	environment := newFakeUpstreams(config)
	setFailOnce(environment, "ca-signing", errors.New("upstream unavailable"))
	prepared := &fakePreparedPublisher{}
	coordinator := newTestCoordinator(
		t,
		config,
		store,
		environment,
		prepared,
		coordinatorHooks{},
	)
	if err := coordinator.StartBootstrap(context.Background()); err == nil {
		t.Fatal("upstream failure unexpectedly succeeded")
	}
	snapshot, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.State != JournalFailed {
		t.Fatalf("journal state = %q, want failed", snapshot.State)
	}
	if snapshot.Failure == nil {
		t.Fatal("journal failure record is nil")
	}
	if snapshot.Failure.Step != StepTPMKeyManagerCASigning {
		t.Fatalf("failure step = %q, want %q", snapshot.Failure.Step, StepTPMKeyManagerCASigning)
	}
	if snapshot.Failure.Code != failureAction {
		t.Fatalf("failure code = %q, want %q", snapshot.Failure.Code, failureAction)
	}
	if snapshot.Failure.Message == "" {
		t.Fatal("failure message is empty")
	}
	if snapshot.Failure.At.IsZero() {
		t.Fatal("failure time is zero")
	}

	reloaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.State != JournalFailed {
		t.Fatalf("reloaded state = %q, want failed", reloaded.State)
	}
	if reloaded.Failure == nil ||
		reloaded.Failure.Step != StepTPMKeyManagerCASigning ||
		reloaded.Failure.Code != failureAction {
		t.Fatalf("reloaded failure = %#v", reloaded.Failure)
	}
}

func TestJournalReadinessIsDurable(t *testing.T) {
	t.Parallel()

	config := validTestConfiguration()
	store, err := NewFileJournalStore(
		filepath.Join(secureTempDir(t), "journal.json"),
	)
	if err != nil {
		t.Fatal(err)
	}
	environment := newFakeUpstreams(config)
	prepared := &fakePreparedPublisher{}
	crash := errors.New("stop after prepared commit")
	coordinator := newTestCoordinator(
		t,
		config,
		store,
		environment,
		prepared,
		coordinatorHooks{
			afterCommit: func(step Step) error {
				if step == StepSPIRETPMConfig {
					return crash
				}
				return nil
			},
		},
	)
	if err := coordinator.StartBootstrap(context.Background()); !errors.Is(err, crash) {
		t.Fatalf("StartBootstrap() error = %v, want crash", err)
	}
	snapshot, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.Prepared {
		t.Fatal("journal prepared flag is false after step 5")
	}
	if snapshot.PreparedAt == nil || snapshot.PreparedAt.IsZero() {
		t.Fatal("journal prepared time is zero after step 5")
	}
	if len(snapshot.Steps) != stepIndex(StepSPIRETPMConfig)+1 {
		t.Fatalf("completed steps = %d, want 5", len(snapshot.Steps))
	}
	if snapshot.State == JournalComplete {
		t.Fatal("journal is complete after step 5")
	}

	reloaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded.Prepared {
		t.Fatal("reloaded prepared flag is false")
	}
	if reloaded.PreparedAt == nil || reloaded.PreparedAt.IsZero() {
		t.Fatal("reloaded prepared time is zero")
	}
}

func TestStartBootstrapOnEmptyJournalCreatesTransaction(t *testing.T) {
	t.Parallel()

	config := validTestConfiguration()
	store, err := NewFileJournalStore(
		filepath.Join(secureTempDir(t), "journal.json"),
	)
	if err != nil {
		t.Fatal(err)
	}
	environment := newFakeUpstreams(config)
	prepared := &fakePreparedPublisher{}
	coordinator := newTestCoordinator(
		t,
		config,
		store,
		environment,
		prepared,
		coordinatorHooks{},
	)
	if err := coordinator.StartBootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Version != JournalVersion {
		t.Fatalf("journal version = %d, want %d", snapshot.Version, JournalVersion)
	}
	if snapshot.TransactionID == "" {
		t.Fatal("journal has no transaction ID after first start")
	}
	if snapshot.TransactionID != testTransactionID {
		t.Fatalf(
			"transaction ID = %q, want %q",
			snapshot.TransactionID,
			testTransactionID,
		)
	}
	if snapshot.State != JournalComplete {
		t.Fatalf("journal state = %q, want complete", snapshot.State)
	}
	if len(snapshot.Steps) != len(orderedSteps) {
		t.Fatalf("completed steps = %d, want %d", len(snapshot.Steps), len(orderedSteps))
	}
}

func TestPurposeBoundSigningRejectsWrongPurpose(t *testing.T) {
	t.Parallel()

	config := validTestConfiguration()
	environment := newFakeUpstreams(config)
	prepared := &fakePreparedPublisher{}
	store := &memoryJournalStore{}

	differentPurpose := CARequest{
		Purpose:         SigningPurpose("unauthorized-signing"),
		Artifact:        config.Artifacts.CARequest,
		KeyInventory:    config.Authority.TPMKeyInventory,
		IssuerHierarchy: config.Authority.IssuerHierarchy,
	}
	if _, err := environment.EnsureSigning(
		context.Background(),
		Operation{
			TransactionID:       testTransactionID,
			IdempotencyKey:      idempotencyKey(testTransactionID, StepTPMKeyManagerCASigning),
			BootstrapVersion:    config.BootstrapVersion,
			ConfigurationSHA256: mustDigest(t, config),
			Step:                StepTPMKeyManagerCASigning,
			FieldManager:        bootstrapFieldManager,
			Compatibility:       config.Authority.Compatibility,
		},
		differentPurpose,
	); err == nil {
		t.Fatal("EnsureSigning accepted unauthorized purpose")
	}
	if _, err := environment.EnsureSigning(
		context.Background(),
		Operation{
			TransactionID:       testTransactionID,
			IdempotencyKey:      idempotencyKey(testTransactionID, StepTPMKeyManagerCASigning),
			BootstrapVersion:    config.BootstrapVersion,
			ConfigurationSHA256: mustDigest(t, config),
			Step:                StepTPMKeyManagerCASigning,
			FieldManager:        bootstrapFieldManager,
			Compatibility:       config.Authority.Compatibility,
		},
		CARequest{
			Purpose:         SigningPurposeBootstrapCA,
			Artifact:        config.Artifacts.CARequest,
			KeyInventory:    config.Authority.TPMKeyInventory,
			IssuerHierarchy: config.Authority.IssuerHierarchy,
		},
	); err != nil {
		t.Fatalf("EnsureSigning rejected authorized purpose: %v", err)
	}
	_ = environment
	_ = prepared
	_ = store
}

func TestConfigurationDigestIsDeterministic(t *testing.T) {
	t.Parallel()

	config := validTestConfiguration()
	first, err := config.validate()
	if err != nil {
		t.Fatal(err)
	}
	for range 100 {
		second, err := config.validate()
		if err != nil {
			t.Fatal(err)
		}
		if first != second {
			t.Fatalf("configuration digest is not deterministic: %q != %q", first, second)
		}
	}
}

func TestValidateEvidenceShapeRejectsMalformedEvidence(t *testing.T) {
	t.Parallel()

	for _, step := range Steps() {
		step := step
		t.Run(string(step), func(t *testing.T) {
			t.Parallel()

			config := validTestConfiguration()
			expected := expectedComponents(step)

			wrongComponentEvidence := Evidence{
				Observations: []Observation{
					{
						Component:      Component("wrong-component"),
						Version:        config.Artifacts.Kubelet.Version,
						ArtifactSHA256: config.Artifacts.Kubelet.SHA256,
						ResourceSHA256: testResourceDigest("resource"),
						Ready:          true,
					},
				},
			}
			if step == StepApplyClusterConfigs || step == StepMarkComplete {
				wrongComponentEvidence = Evidence{
					Observations: []Observation{
						{Component: Component("wrong"), Version: "v1", ArtifactSHA256: testResourceDigest("a"), ResourceSHA256: testResourceDigest("b"), Ready: true},
						{Component: Component("wrong"), Version: "v1", ArtifactSHA256: testResourceDigest("a"), ResourceSHA256: testResourceDigest("b"), Ready: true},
						{Component: Component("wrong"), Version: "v1", ArtifactSHA256: testResourceDigest("a"), ResourceSHA256: testResourceDigest("b"), Ready: true},
						{Component: Component("wrong"), Version: "v1", ArtifactSHA256: testResourceDigest("a"), ResourceSHA256: testResourceDigest("b"), Ready: true},
						{Component: Component("wrong"), Version: "v1", ArtifactSHA256: testResourceDigest("a"), ResourceSHA256: testResourceDigest("b"), Ready: true},
					},
				}
			}
			if err := validateEvidenceShape(step, wrongComponentEvidence); err == nil {
				t.Fatalf("validateEvidenceShape accepted wrong component for step %q", step)
			}

			emptyEvidence := Evidence{}
			if err := validateEvidenceShape(step, emptyEvidence); err == nil {
				t.Fatalf("validateEvidenceShape accepted empty evidence for step %q", step)
			}

			if step == StepApplyClusterConfigs || step == StepMarkComplete {
				truncatedEvidence := Evidence{
					Observations: []Observation{
						{
							Component:      expected[0],
							Version:        config.Artifacts.Cluster.Version,
							ArtifactSHA256: config.Artifacts.Cluster.SHA256,
							ResourceSHA256: testResourceDigest("resource"),
							Ready:          step == StepMarkComplete,
						},
					},
				}
				if err := validateEvidenceShape(step, truncatedEvidence); err == nil {
					t.Fatalf("validateEvidenceShape accepted truncated evidence for step %q", step)
				}
			}

			emptyVersionEvidence := Evidence{
				Observations: []Observation{
					{
						Component:      expected[0],
						Version:        "",
						ArtifactSHA256: testResourceDigest("artifact"),
						ResourceSHA256: testResourceDigest("resource"),
						Ready:          true,
					},
				},
			}
			if step == StepApplyClusterConfigs || step == StepMarkComplete {
				emptyVersionEvidence = Evidence{
					Observations: make([]Observation, len(expected)),
				}
				for i, comp := range expected {
					emptyVersionEvidence.Observations[i] = Observation{
						Component:      comp,
						Version:        "",
						ArtifactSHA256: testResourceDigest("artifact"),
						ResourceSHA256: testResourceDigest("resource"),
						Ready:          step == StepMarkComplete,
					}
				}
			}
			if err := validateEvidenceShape(step, emptyVersionEvidence); err == nil {
				t.Fatalf("validateEvidenceShape accepted empty version for step %q", step)
			}

			badDigestEvidence := Evidence{
				Observations: []Observation{
					{
						Component:      expected[0],
						Version:        config.Artifacts.Kubelet.Version,
						ArtifactSHA256: "not-a-valid-sha256",
						ResourceSHA256: testResourceDigest("resource"),
						Ready:          true,
					},
				},
			}
			if step == StepApplyClusterConfigs || step == StepMarkComplete {
				badDigestEvidence = Evidence{
					Observations: make([]Observation, len(expected)),
				}
				for i, comp := range expected {
					badDigestEvidence.Observations[i] = Observation{
						Component:      comp,
						Version:        config.Artifacts.Kubelet.Version,
						ArtifactSHA256: "not-a-valid-sha256",
						ResourceSHA256: testResourceDigest("resource"),
						Ready:          step == StepMarkComplete,
					}
				}
			}
			if err := validateEvidenceShape(step, badDigestEvidence); err == nil {
				t.Fatalf("validateEvidenceShape accepted bad digest for step %q", step)
			}

			notReadyEvidence := Evidence{
				Observations: []Observation{
					{
						Component:      expected[0],
						Version:        config.Artifacts.Kubelet.Version,
						ArtifactSHA256: config.Artifacts.Kubelet.SHA256,
						ResourceSHA256: testResourceDigest("resource"),
						Ready:          false,
					},
				},
			}
			if step == StepApplyClusterConfigs || step == StepMarkComplete {
				notReadyEvidence = Evidence{
					Observations: make([]Observation, len(expected)),
				}
				for i, comp := range expected {
					notReadyEvidence.Observations[i] = Observation{
						Component:      comp,
						Version:        config.Artifacts.Kubelet.Version,
						ArtifactSHA256: config.Artifacts.Kubelet.SHA256,
						ResourceSHA256: testResourceDigest("resource"),
						Ready:          false,
					}
				}
			}
			isReadinessStep := step == StepWaitControlPlane ||
				step == StepApplyClusterConfigs ||
				step == StepMarkComplete
			if err := validateEvidenceShape(step, notReadyEvidence); isReadinessStep && err == nil {
				t.Fatalf("validateEvidenceShape accepted not-ready evidence for readiness step %q", step)
			}
		})
	}
}

func TestAtomicValidationRejectsEmptyOrWrongComponentArtifacts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Configuration)
	}{
		{
			name: "empty CA request content",
			mutate: func(config *Configuration) {
				config.Artifacts.CARequest.Content = nil
				config.Artifacts.CARequest.SHA256 = ""
			},
		},
		{
			name: "CA request wrong name",
			mutate: func(config *Configuration) {
				config.Artifacts.CARequest = testArtifact(
					"wrong-name",
					config.BootstrapVersion,
					"public certificate request",
				)
			},
		},
		{
			name: "empty kubelet content",
			mutate: func(config *Configuration) {
				config.Artifacts.Kubelet.Content = nil
				config.Artifacts.Kubelet.SHA256 = ""
			},
		},
		{
			name: "kubelet wrong version",
			mutate: func(config *Configuration) {
				config.Artifacts.Kubelet.Version = "v1.34.0"
			},
		},
		{
			name: "empty Calico content",
			mutate: func(config *Configuration) {
				config.Artifacts.Calico.Content = nil
				config.Artifacts.Calico.SHA256 = ""
			},
		},
		{
			name: "empty Istio content",
			mutate: func(config *Configuration) {
				config.Artifacts.Istio.Content = nil
				config.Artifacts.Istio.SHA256 = ""
			},
		},
		{
			name: "empty SPIRE content",
			mutate: func(config *Configuration) {
				config.Artifacts.SPIRE.Content = nil
				config.Artifacts.SPIRE.SHA256 = ""
			},
		},
		{
			name: "SPIRE wrong TPM reference",
			mutate: func(config *Configuration) {
				config.Artifacts.SPIRE = testArtifact(
					ArtifactSPIRE,
					config.Versions.SPIRE,
					"plugin = tpm_devid\nreference = different-handle\n",
				)
			},
		},
		{
			name: "empty Dex content",
			mutate: func(config *Configuration) {
				config.Artifacts.Dex.Content = nil
				config.Artifacts.Dex.SHA256 = ""
			},
		},
		{
			name: "empty control plane content",
			mutate: func(config *Configuration) {
				config.Artifacts.ControlPlane.Content = nil
				config.Artifacts.ControlPlane.SHA256 = ""
			},
		},
		{
			name: "empty topology contract",
			mutate: func(config *Configuration) {
				config.Authority.KubernetesTopology.Content = nil
				config.Authority.KubernetesTopology.SHA256 = ""
			},
		},
		{
			name: "empty key inventory contract",
			mutate: func(config *Configuration) {
				config.Authority.TPMKeyInventory.Content = nil
				config.Authority.TPMKeyInventory.SHA256 = ""
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config := validTestConfiguration()
			test.mutate(&config)
			if _, err := config.validate(); err == nil {
				t.Fatal("configuration unexpectedly validated")
			}
		})
	}
}

func TestIncompatibleConfigurationRejectionCoversAllBoundaryMutations(t *testing.T) {
	t.Parallel()

	config := validTestConfiguration()
	store, err := NewFileJournalStore(
		filepath.Join(secureTempDir(t), "journal.json"),
	)
	if err != nil {
		t.Fatal(err)
	}
	environment := newFakeUpstreams(config)
	prepared := &fakePreparedPublisher{}
	crash := errors.New("stop after first commit")
	coordinator := newTestCoordinator(
		t,
		config,
		store,
		environment,
		prepared,
		coordinatorHooks{
			afterCommit: func(step Step) error {
				if step == StepTPMKeyManagerCASigning {
					return crash
				}
				return nil
			},
		},
	)
	if err := coordinator.StartBootstrap(context.Background()); !errors.Is(err, crash) {
		t.Fatalf("StartBootstrap() error = %v, want crash", err)
	}

	mutations := []struct {
		name   string
		mutate func(*Configuration)
	}{
		{
			name: "changed ULA",
			mutate: func(c *Configuration) {
				c.ULA = netip.MustParsePrefix("fdab:1234::/48")
			},
		},
		{
			name: "changed TPM reference",
			mutate: func(c *Configuration) {
				c.TPMDeviceKeyReference = "tpm-device-key:0x81010099"
				c.Artifacts.SPIRE = testArtifact(
					ArtifactSPIRE,
					c.Versions.SPIRE,
					"reference = tpm-device-key:0x81010099\n",
				)
			},
		},
		{
			name: "changed Dex version",
			mutate: func(c *Configuration) {
				c.Versions.Dex = "v2.46.0"
				c.Artifacts.Dex = testArtifact(
					ArtifactDex,
					"v2.46.0",
					"different dex version content\n",
				)
			},
		},
		{
			name: "changed Kubernetes topology contract",
			mutate: func(c *Configuration) {
				c.Authority.KubernetesTopology = testArtifact(
					ArtifactTopologyContract,
					"decision-006-r2",
					"changed topology\n",
				)
			},
		},
		{
			name: "changed compatibility matrix",
			mutate: func(c *Configuration) {
				c.Authority.Compatibility = testArtifact(
					ArtifactCompatibility,
					"compatibility-r2",
					"new compatibility matrix\n",
				)
			},
		},
	}
	for _, mutation := range mutations {
		mutation := mutation
		t.Run(mutation.name, func(t *testing.T) {
			t.Parallel()
			changed := validTestConfiguration()
			mutation.mutate(&changed)
			changedEnvironment := newFakeUpstreams(changed)
			resumed := newTestCoordinator(
				t,
				changed,
				store,
				changedEnvironment,
				prepared,
				coordinatorHooks{},
			)
			err := resumed.StartBootstrap(context.Background())
			if !errors.Is(err, ErrIncompatibleConfiguration) {
				t.Fatalf("resume error = %v, want incompatible configuration", err)
			}
			if got := actionCalls(changedEnvironment); len(got) != 0 {
				t.Fatalf("changed configuration executed actions: %#v", got)
			}
		})
	}
}

func TestFullBootstrapCompletesDeterministicallyWithSimulator(t *testing.T) {
	t.Parallel()

	config := validTestConfiguration()
	store, err := NewFileJournalStore(
		filepath.Join(secureTempDir(t), "journal.json"),
	)
	if err != nil {
		t.Fatal(err)
	}
	environment := newFakeUpstreams(config)
	prepared := &fakePreparedPublisher{}
	coordinator := newTestCoordinator(
		t,
		config,
		store,
		environment,
		prepared,
		coordinatorHooks{},
	)
	if err := coordinator.StartBootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	status, err := coordinator.GetStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.State != StatusComplete {
		t.Fatalf("status = %q, want complete", status.State)
	}
	if status.CurrentStep != StepMarkComplete {
		t.Fatalf("current step = %q, want %q", status.CurrentStep, StepMarkComplete)
	}

	snapshot, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.TransactionID != testTransactionID {
		t.Fatalf(
			"transaction ID = %q, want %q",
			snapshot.TransactionID,
			testTransactionID,
		)
	}
	if len(snapshot.Steps) != len(Steps()) {
		t.Fatalf("completed steps = %d, want %d", len(snapshot.Steps), len(Steps()))
	}
	for _, step := range snapshot.Steps {
		if step.CompletedAt.IsZero() {
			t.Fatalf("step %q has zero completion time", step.Step)
		}
	}

	creations := resourceCreations(environment)
	for action, count := range creations {
		if count != 1 {
			t.Fatalf("resource %q creation count = %d, want 1", action, count)
		}
	}
	calls := actionCalls(environment)
	mandatoryActions := []string{
		"ca-signing", "kubelet", "calico-ipv6", "istio-ingress", "spire-tpm",
		"api-server", "control-plane",
		"kubernetes-reconcile", "calico-reconcile", "istio-reconcile",
		"spire-reconcile", "dex-reconcile",
		"kubernetes-ready", "calico-ready", "istio-ready",
		"spire-ready", "dex-ready",
	}
	for _, action := range mandatoryActions {
		if calls[action] == 0 {
			t.Fatalf("action %q was never called", action)
		}
	}

	publishCalls, verifyCalls := prepared.counts()
	if publishCalls == 0 {
		t.Fatal("prepared publisher was never published")
	}
	if verifyCalls == 0 {
		t.Fatal("prepared publisher was never verified")
	}
}

func TestGetStatusBeforeStartReportsNotStarted(t *testing.T) {
	t.Parallel()

	config := validTestConfiguration()
	store, err := NewFileJournalStore(
		filepath.Join(secureTempDir(t), "journal.json"),
	)
	if err != nil {
		t.Fatal(err)
	}
	environment := newFakeUpstreams(config)
	prepared := &fakePreparedPublisher{}
	coordinator := newTestCoordinator(
		t,
		config,
		store,
		environment,
		prepared,
		coordinatorHooks{},
	)
	status, err := coordinator.GetStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.State != StatusNotStarted {
		t.Fatalf("status before start = %q, want not_started", status.State)
	}
	if status.CurrentStep != StepTPMKeyManagerCASigning {
		t.Fatalf(
			"status current step = %q, want %q",
			status.CurrentStep,
			StepTPMKeyManagerCASigning,
		)
	}
	if status.Message != "bootstrap has not started" {
		t.Fatalf("status message = %q", status.Message)
	}
}
