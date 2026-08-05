// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package bootstrap

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"
)

var (
	// ErrIncompatibleConfiguration prevents a persisted transaction from being
	// resumed with changed versions, topology, policies, ULA, or artifacts.
	ErrIncompatibleConfiguration = errors.New(
		"bootstrap configuration is incompatible with the durable transaction",
	)
	// ErrDependenciesUnavailable indicates incomplete production composition.
	ErrDependenciesUnavailable = errors.New(
		"bootstrap dependencies are unavailable",
	)
)

// Dependencies are the only mutable external boundaries used by the
// coordinator.
type Dependencies struct {
	CA         CASigner
	Kubernetes KubernetesInstaller
	Calico     CalicoInstaller
	Istio      IstioInstaller
	SPIRE      SPIREInstaller
	Dex        DexInstaller
	Prepared   PreparedPublisher
}

type clock interface {
	Now() time.Time
}

type wallClock struct{}

func (wallClock) Now() time.Time {
	return time.Now()
}

type coordinatorHooks struct {
	afterIntent func(Step) error
	afterAction func(Step) error
	afterCommit func(Step) error
}

type coordinatorOptions struct {
	clock       clock
	newID       func() (string, error)
	hooks       coordinatorHooks
}

// Coordinator durably serializes StartBootstrap calls and exposes current
// status without adding any transport or public RPC surface.
type Coordinator struct {
	config       Configuration
	configDigest string
	store        JournalStore
	dependencies Dependencies
	clock        clock
	newID        func() (string, error)
	hooks        coordinatorHooks

	runMu sync.Mutex
}

// NewCoordinator validates every authority and artifact input before returning
// a usable reconciler.
func NewCoordinator(
	config Configuration,
	store JournalStore,
	dependencies Dependencies,
) (*Coordinator, error) {
	return newCoordinator(config, store, dependencies, coordinatorOptions{})
}

func newCoordinator(
	config Configuration,
	store JournalStore,
	dependencies Dependencies,
	options coordinatorOptions,
) (*Coordinator, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: journal store", ErrDependenciesUnavailable)
	}
	if dependencies.CA == nil ||
		dependencies.Kubernetes == nil ||
		dependencies.Calico == nil ||
		dependencies.Istio == nil ||
		dependencies.SPIRE == nil ||
		dependencies.Dex == nil ||
		dependencies.Prepared == nil {
		return nil, fmt.Errorf(
			"%w: every named upstream and prepared publisher is required",
			ErrDependenciesUnavailable,
		)
	}
	digest, err := config.validate()
	if err != nil {
		return nil, fmt.Errorf("validate bootstrap configuration: %w", err)
	}
	if options.clock == nil {
		options.clock = wallClock{}
	}
	if options.newID == nil {
		options.newID = randomTransactionID
	}
	return &Coordinator{
		config:       cloneConfiguration(config),
		configDigest: digest,
		store:        store,
		dependencies: dependencies,
		clock:        options.clock,
		newID:        options.newID,
		hooks:        options.hooks,
	}, nil
}

// StartBootstrap starts or resumes the sole durable transaction. Each
// completed step is verified read-only before the next action. The step
// methods themselves are idempotent against Operation.IdempotencyKey so a
// crash after an external commit cannot rotate or recreate a result.
func (c *Coordinator) StartBootstrap(ctx context.Context) error {
	c.runMu.Lock()
	defer c.runMu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}
	journal, err := c.store.Load()
	if err != nil {
		return fmt.Errorf("load bootstrap journal: %w", err)
	}
	if journal.Version == 0 {
		journal, err = c.initializeJournal(ctx)
		if err != nil {
			return err
		}
	}
	if err := c.requireCompatible(journal); err != nil {
		return err
	}

	if err := c.verifyCompleted(ctx, journal); err != nil {
		step := verificationFailureStep(journal, err)
		saveErr := c.saveFailure(&journal, step, failureVerification)
		return errors.Join(
			fmt.Errorf("verify completed bootstrap state: %w", err),
			saveErr,
		)
	}
	if journal.Prepared {
		if err := c.publishPrepared(ctx); err != nil {
			saveErr := c.saveFailure(
				&journal,
				StepSPIRETPMConfig,
				failurePrepared,
			)
			return errors.Join(
				fmt.Errorf("publish prepared bootstrap readiness: %w", err),
				saveErr,
			)
		}
	}
	if len(journal.Steps) == len(orderedSteps) {
		if journal.State != JournalComplete || journal.Failure != nil {
			next := cloneJournal(journal)
			next.State = JournalComplete
			next.Failure = nil
			next.Current = nil
			if err := c.advanceAndSave(&journal, &next); err != nil {
				return fmt.Errorf("restore verified complete state: %w", err)
			}
		}
		return nil
	}
	if journal.State == JournalFailed || journal.Failure != nil {
		next := cloneJournal(journal)
		next.State = JournalInProgress
		next.Failure = nil
		if err := c.advanceAndSave(&journal, &next); err != nil {
			return fmt.Errorf("resume failed bootstrap transaction: %w", err)
		}
	}

	for len(journal.Steps) < len(orderedSteps) {
		if err := ctx.Err(); err != nil {
			return err
		}
		step := orderedSteps[len(journal.Steps)]
		if err := c.beginAttempt(&journal, step); err != nil {
			return err
		}
		if c.hooks.afterIntent != nil {
			if err := c.hooks.afterIntent(step); err != nil {
				return err
			}
		}
		evidence, err := c.executeStep(ctx, step, journal)
		if err != nil {
			saveErr := c.saveFailure(&journal, step, failureAction)
			return errors.Join(
				fmt.Errorf("execute bootstrap step %q: %w", step, err),
				saveErr,
			)
		}
		if err := c.validateEvidence(step, evidence); err != nil {
			saveErr := c.saveFailure(&journal, step, failureVerification)
			return errors.Join(
				fmt.Errorf("validate bootstrap step %q evidence: %w", step, err),
				saveErr,
			)
		}
		record := StepRecord{
			Step:     step,
			Evidence: evidence,
		}
		if err := c.verifyRecord(ctx, record, journal); err != nil {
			saveErr := c.saveFailure(&journal, step, failureVerification)
			return errors.Join(
				fmt.Errorf("verify bootstrap step %q result: %w", step, err),
				saveErr,
			)
		}
		if c.hooks.afterAction != nil {
			if err := c.hooks.afterAction(step); err != nil {
				return err
			}
		}
		if err := c.commitStep(&journal, record); err != nil {
			return err
		}
		if c.hooks.afterCommit != nil {
			if err := c.hooks.afterCommit(step); err != nil {
				return err
			}
		}
		if step == StepSPIRETPMConfig {
			if err := c.publishPrepared(ctx); err != nil {
				saveErr := c.saveFailure(
					&journal,
					step,
					failurePrepared,
				)
				return errors.Join(
					fmt.Errorf(
						"publish prepared bootstrap readiness: %w",
						err,
					),
					saveErr,
				)
			}
		}
	}
	return nil
}

// GetStatus reports only durable state. Prepared remains in-progress, and
// complete is impossible unless the ninth verified record is committed.
func (c *Coordinator) GetStatus(ctx context.Context) (Status, error) {
	if err := ctx.Err(); err != nil {
		return Status{}, err
	}
	journal, err := c.store.Load()
	if err != nil {
		return Status{}, fmt.Errorf("load bootstrap status: %w", err)
	}
	if journal.Version == 0 {
		return Status{
			State:       StatusNotStarted,
			CurrentStep: StepTPMKeyManagerCASigning,
			Message:     "bootstrap has not started",
		}, nil
	}
	if err := c.requireCompatible(journal); err != nil {
		return Status{}, err
	}
	status := Status{
		UpdatedAt: journal.UpdatedAt,
	}
	switch journal.State {
	case JournalComplete:
		status.State = StatusComplete
		status.CurrentStep = StepMarkComplete
		status.Message = "all nine bootstrap steps are verified complete"
	case JournalFailed:
		status.State = StatusFailed
		status.CurrentStep = journal.Failure.Step
		status.Message = journal.Failure.Message
	default:
		status.State = StatusInProgress
		if journal.Current != nil {
			status.CurrentStep = journal.Current.Step
		} else {
			status.CurrentStep = orderedSteps[len(journal.Steps)]
		}
		if journal.Prepared {
			status.Message = "bootstrap prerequisites are prepared; cluster bootstrap is in progress"
		} else {
			status.Message = "bootstrap prerequisites are not yet prepared"
		}
	}
	return status, nil
}

func (c *Coordinator) initializeJournal(ctx context.Context) (Journal, error) {
	if err := ctx.Err(); err != nil {
		return Journal{}, err
	}
	transactionID, err := c.newID()
	if err != nil {
		return Journal{}, fmt.Errorf("create bootstrap transaction ID: %w", err)
	}
	if !validTransactionID(transactionID) {
		return Journal{}, errors.New(
			"bootstrap transaction ID generator returned an invalid ID",
		)
	}
	now, err := c.now()
	if err != nil {
		return Journal{}, err
	}
	journal := Journal{
		Version:             JournalVersion,
		Revision:            1,
		TransactionID:       transactionID,
		BootstrapVersion:    c.config.BootstrapVersion,
		ConfigurationSHA256: c.configDigest,
		State:               JournalInProgress,
		Steps:               []StepRecord{},
		UpdatedAt:           now,
	}
	if err := c.store.Save(0, journal); err != nil {
		return Journal{}, fmt.Errorf("create bootstrap journal: %w", err)
	}
	return journal, nil
}

func (c *Coordinator) beginAttempt(journal *Journal, step Step) error {
	next := cloneJournal(*journal)
	now, err := c.now()
	if err != nil {
		return err
	}
	if next.Current == nil {
		next.Current = &Attempt{
			Step:      step,
			StartedAt: now,
			Attempts:  1,
		}
	} else {
		if next.Current.Step != step {
			return errors.New("durable current step does not match resume step")
		}
		if next.Current.Attempts == math.MaxUint64 {
			return errors.New("bootstrap step attempt counter is exhausted")
		}
		next.Current.Attempts++
	}
	next.State = JournalInProgress
	next.Failure = nil
	if err := c.advanceAndSave(journal, &next); err != nil {
		return fmt.Errorf("record bootstrap step %q intent: %w", step, err)
	}
	return nil
}

func (c *Coordinator) commitStep(
	journal *Journal,
	record StepRecord,
) error {
	next := cloneJournal(*journal)
	now, err := c.now()
	if err != nil {
		return err
	}
	record.CompletedAt = now
	next.Steps = append(next.Steps, record)
	next.Current = nil
	next.Failure = nil
	if record.Step == StepSPIRETPMConfig {
		next.Prepared = true
		preparedAt := now
		next.PreparedAt = &preparedAt
	}
	if record.Step == StepMarkComplete {
		next.State = JournalComplete
	} else {
		next.State = JournalInProgress
	}
	if err := c.advanceAndSave(journal, &next); err != nil {
		return fmt.Errorf("commit bootstrap step %q: %w", record.Step, err)
	}
	return nil
}

func (c *Coordinator) saveFailure(
	journal *Journal,
	step Step,
	code string,
) error {
	next := cloneJournal(*journal)
	now, err := c.now()
	if err != nil {
		return err
	}
	next.State = JournalFailed
	next.Failure = &Failure{
		Step:    step,
		Code:    code,
		Message: failureMessage(step, code),
		At:      now,
	}
	if err := c.advanceAndSave(journal, &next); err != nil {
		return fmt.Errorf("persist sanitized bootstrap failure: %w", err)
	}
	return nil
}

func (c *Coordinator) advanceAndSave(
	current *Journal,
	next *Journal,
) error {
	if current.Revision == math.MaxUint64 {
		return errors.New("bootstrap journal revision is exhausted")
	}
	now, err := c.now()
	if err != nil {
		return err
	}
	next.Revision = current.Revision + 1
	next.UpdatedAt = now
	if err := c.store.Save(current.Revision, *next); err != nil {
		return err
	}
	*current = cloneJournal(*next)
	return nil
}

func (c *Coordinator) executeStep(
	ctx context.Context,
	step Step,
	journal Journal,
) (Evidence, error) {
	operation := c.operation(journal, step)
	switch step {
	case StepTPMKeyManagerCASigning:
		observation, err := c.dependencies.CA.EnsureSigning(
			ctx,
			operation,
			c.caRequest(),
		)
		return evidenceOf(observation), err
	case StepKubeletConfig:
		observation, err := c.dependencies.Kubernetes.PrepareKubelet(
			ctx,
			operation,
			c.config.Artifacts.Kubelet,
			c.config.Authority.KubernetesTopology,
		)
		return evidenceOf(observation), err
	case StepCalicoIPv6:
		observation, err := c.dependencies.Calico.PrepareIPv6(
			ctx,
			operation,
			c.config.ULA,
			c.config.Artifacts.Calico,
		)
		return evidenceOf(observation), err
	case StepIstioIngress:
		observation, err := c.dependencies.Istio.PrepareIngress(
			ctx,
			operation,
			c.config.Artifacts.Istio,
			c.config.Authority.IngressTokenFlow,
		)
		return evidenceOf(observation), err
	case StepSPIRETPMConfig:
		observation, err := c.dependencies.SPIRE.PrepareTPM(
			ctx,
			operation,
			c.spireRequest(),
		)
		return evidenceOf(observation), err
	case StepInitializeAPIServer:
		observation, err := c.dependencies.Kubernetes.InitializeAPIServer(
			ctx,
			operation,
			c.config.Artifacts.ControlPlane,
			c.config.Authority.KubernetesTopology,
		)
		return evidenceOf(observation), err
	case StepWaitControlPlane:
		observation, err := c.dependencies.Kubernetes.WaitControlPlane(
			ctx,
			operation,
			c.config.Artifacts.ControlPlane,
		)
		return evidenceOf(observation), err
	case StepApplyClusterConfigs:
		return c.applyClusterConfigs(ctx, operation)
	case StepMarkComplete:
		if err := c.verifyCompleted(ctx, journal); err != nil {
			return Evidence{}, fmt.Errorf(
				"reverify steps before completion: %w",
				err,
			)
		}
		return c.checkAllReady(ctx, operation)
	default:
		return Evidence{}, fmt.Errorf("unknown bootstrap step %q", step)
	}
}

func (c *Coordinator) applyClusterConfigs(
	ctx context.Context,
	operation Operation,
) (Evidence, error) {
	observations := make([]Observation, 0, 5)
	kubernetes, err := c.dependencies.Kubernetes.Reconcile(
		ctx,
		operation,
		c.config.Artifacts.Cluster,
	)
	if err != nil {
		return Evidence{}, err
	}
	observations = append(observations, kubernetes)
	calico, err := c.dependencies.Calico.Reconcile(
		ctx,
		operation,
		c.config.Artifacts.Calico,
	)
	if err != nil {
		return Evidence{}, err
	}
	observations = append(observations, calico)
	istio, err := c.dependencies.Istio.Reconcile(
		ctx,
		operation,
		c.config.Artifacts.Istio,
	)
	if err != nil {
		return Evidence{}, err
	}
	observations = append(observations, istio)
	spire, err := c.dependencies.SPIRE.Reconcile(
		ctx,
		operation,
		c.config.Artifacts.SPIRE,
	)
	if err != nil {
		return Evidence{}, err
	}
	observations = append(observations, spire)
	dex, err := c.dependencies.Dex.Reconcile(
		ctx,
		operation,
		c.dexRequest(),
	)
	if err != nil {
		return Evidence{}, err
	}
	observations = append(observations, dex)
	return Evidence{Observations: observations}, nil
}

func (c *Coordinator) checkAllReady(
	ctx context.Context,
	operation Operation,
) (Evidence, error) {
	observations := make([]Observation, 0, 5)
	kubernetes, err := c.dependencies.Kubernetes.CheckReady(ctx, operation)
	if err != nil {
		return Evidence{}, err
	}
	observations = append(observations, kubernetes)
	calico, err := c.dependencies.Calico.CheckReady(ctx, operation)
	if err != nil {
		return Evidence{}, err
	}
	observations = append(observations, calico)
	istio, err := c.dependencies.Istio.CheckReady(ctx, operation)
	if err != nil {
		return Evidence{}, err
	}
	observations = append(observations, istio)
	spire, err := c.dependencies.SPIRE.CheckReady(ctx, operation)
	if err != nil {
		return Evidence{}, err
	}
	observations = append(observations, spire)
	dex, err := c.dependencies.Dex.CheckReady(ctx, operation)
	if err != nil {
		return Evidence{}, err
	}
	observations = append(observations, dex)
	return Evidence{Observations: observations}, nil
}

func (c *Coordinator) verifyCompleted(
	ctx context.Context,
	journal Journal,
) error {
	for _, record := range journal.Steps {
		if err := c.validateEvidence(record.Step, record.Evidence); err != nil {
			return &recordVerificationError{
				step: record.Step,
				err:  err,
			}
		}
		if err := c.verifyRecord(ctx, record, journal); err != nil {
			return &recordVerificationError{
				step: record.Step,
				err:  err,
			}
		}
	}
	return nil
}

func (c *Coordinator) verifyRecord(
	ctx context.Context,
	record StepRecord,
	journal Journal,
) error {
	operation := c.operation(journal, record.Step)
	observations := record.Evidence.Observations
	switch record.Step {
	case StepTPMKeyManagerCASigning:
		return c.dependencies.CA.VerifySigning(
			ctx,
			operation,
			c.caRequest(),
			observations[0],
		)
	case StepKubeletConfig:
		return c.dependencies.Kubernetes.VerifyKubelet(
			ctx,
			operation,
			c.config.Artifacts.Kubelet,
			c.config.Authority.KubernetesTopology,
			observations[0],
		)
	case StepCalicoIPv6:
		return c.dependencies.Calico.VerifyIPv6(
			ctx,
			operation,
			c.config.ULA,
			c.config.Artifacts.Calico,
			observations[0],
		)
	case StepIstioIngress:
		return c.dependencies.Istio.VerifyIngress(
			ctx,
			operation,
			c.config.Artifacts.Istio,
			c.config.Authority.IngressTokenFlow,
			observations[0],
		)
	case StepSPIRETPMConfig:
		return c.dependencies.SPIRE.VerifyTPM(
			ctx,
			operation,
			c.spireRequest(),
			observations[0],
		)
	case StepInitializeAPIServer:
		return c.dependencies.Kubernetes.VerifyAPIServer(
			ctx,
			operation,
			c.config.Artifacts.ControlPlane,
			c.config.Authority.KubernetesTopology,
			observations[0],
		)
	case StepWaitControlPlane:
		return c.dependencies.Kubernetes.VerifyControlPlane(
			ctx,
			operation,
			c.config.Artifacts.ControlPlane,
			observations[0],
		)
	case StepApplyClusterConfigs:
		return c.verifyReconciled(ctx, operation, observations)
	case StepMarkComplete:
		return c.verifyReady(ctx, operation, observations)
	default:
		return fmt.Errorf("unknown bootstrap step %q", record.Step)
	}
}

func (c *Coordinator) verifyReconciled(
	ctx context.Context,
	operation Operation,
	observations []Observation,
) error {
	if err := c.dependencies.Kubernetes.VerifyReconciled(
		ctx,
		operation,
		c.config.Artifacts.Cluster,
		observations[0],
	); err != nil {
		return err
	}
	if err := c.dependencies.Calico.VerifyReconciled(
		ctx,
		operation,
		c.config.Artifacts.Calico,
		observations[1],
	); err != nil {
		return err
	}
	if err := c.dependencies.Istio.VerifyReconciled(
		ctx,
		operation,
		c.config.Artifacts.Istio,
		observations[2],
	); err != nil {
		return err
	}
	if err := c.dependencies.SPIRE.VerifyReconciled(
		ctx,
		operation,
		c.config.Artifacts.SPIRE,
		observations[3],
	); err != nil {
		return err
	}
	return c.dependencies.Dex.VerifyReconciled(
		ctx,
		operation,
		c.dexRequest(),
		observations[4],
	)
}

func (c *Coordinator) verifyReady(
	ctx context.Context,
	operation Operation,
	observations []Observation,
) error {
	if err := c.dependencies.Kubernetes.VerifyReady(
		ctx,
		operation,
		observations[0],
	); err != nil {
		return err
	}
	if err := c.dependencies.Calico.VerifyReady(
		ctx,
		operation,
		observations[1],
	); err != nil {
		return err
	}
	if err := c.dependencies.Istio.VerifyReady(
		ctx,
		operation,
		observations[2],
	); err != nil {
		return err
	}
	if err := c.dependencies.SPIRE.VerifyReady(
		ctx,
		operation,
		observations[3],
	); err != nil {
		return err
	}
	return c.dependencies.Dex.VerifyReady(
		ctx,
		operation,
		observations[4],
	)
}

func (c *Coordinator) validateEvidence(step Step, evidence Evidence) error {
	if err := validateEvidenceShape(step, evidence); err != nil {
		return err
	}
	expected := c.expectedObservations(step)
	for index, observation := range evidence.Observations {
		if observation.Version != expected[index].Version {
			return fmt.Errorf(
				"%s observation version %q, expected %q",
				observation.Component,
				observation.Version,
				expected[index].Version,
			)
		}
		if observation.ArtifactSHA256 != expected[index].ArtifactSHA256 {
			return fmt.Errorf(
				"%s observation is not bound to the selected artifact",
				observation.Component,
			)
		}
	}
	return nil
}

func (c *Coordinator) expectedObservations(step Step) []Observation {
	observation := func(
		component Component,
		artifact Artifact,
	) Observation {
		return Observation{
			Component:      component,
			Version:        artifact.Version,
			ArtifactSHA256: artifact.SHA256,
		}
	}
	switch step {
	case StepTPMKeyManagerCASigning:
		return []Observation{observation(
			ComponentKeyManager,
			c.config.Artifacts.CARequest,
		)}
	case StepKubeletConfig:
		return []Observation{observation(
			ComponentKubernetes,
			c.config.Artifacts.Kubelet,
		)}
	case StepCalicoIPv6:
		return []Observation{observation(
			ComponentCalico,
			c.config.Artifacts.Calico,
		)}
	case StepIstioIngress:
		return []Observation{observation(
			ComponentIstio,
			c.config.Artifacts.Istio,
		)}
	case StepSPIRETPMConfig:
		return []Observation{observation(
			ComponentSPIRE,
			c.config.Artifacts.SPIRE,
		)}
	case StepInitializeAPIServer, StepWaitControlPlane:
		return []Observation{observation(
			ComponentKubernetes,
			c.config.Artifacts.ControlPlane,
		)}
	case StepApplyClusterConfigs, StepMarkComplete:
		return []Observation{
			observation(ComponentKubernetes, c.config.Artifacts.Cluster),
			observation(ComponentCalico, c.config.Artifacts.Calico),
			observation(ComponentIstio, c.config.Artifacts.Istio),
			observation(ComponentSPIRE, c.config.Artifacts.SPIRE),
			observation(ComponentDex, c.config.Artifacts.Dex),
		}
	default:
		return nil
	}
}

func (c *Coordinator) publishPrepared(ctx context.Context) error {
	if err := c.dependencies.Prepared.Publish(ctx); err != nil {
		return err
	}
	return c.dependencies.Prepared.Verify(ctx)
}

func (c *Coordinator) requireCompatible(journal Journal) error {
	if journal.BootstrapVersion != c.config.BootstrapVersion ||
		journal.ConfigurationSHA256 != c.configDigest {
		return fmt.Errorf(
			"%w: persisted version/digest differ from validated local configuration",
			ErrIncompatibleConfiguration,
		)
	}
	return nil
}

func (c *Coordinator) operation(journal Journal, step Step) Operation {
	return Operation{
		TransactionID:       journal.TransactionID,
		IdempotencyKey:      idempotencyKey(journal.TransactionID, step),
		BootstrapVersion:    journal.BootstrapVersion,
		ConfigurationSHA256: journal.ConfigurationSHA256,
		Step:                step,
		FieldManager:        bootstrapFieldManager,
		ForceOwnership:      false,
		Compatibility:       copyArtifact(c.config.Authority.Compatibility),
	}
}

func (c *Coordinator) caRequest() CARequest {
	return CARequest{
		Purpose:         SigningPurposeBootstrapCA,
		Artifact:        c.config.Artifacts.CARequest,
		KeyInventory:    c.config.Authority.TPMKeyInventory,
		IssuerHierarchy: c.config.Authority.IssuerHierarchy,
	}
}

func (c *Coordinator) spireRequest() SPIRERequest {
	return SPIRERequest{
		Artifact:              c.config.Artifacts.SPIRE,
		TPMDeviceKeyReference: c.config.TPMDeviceKeyReference,
		KeyInventory:          c.config.Authority.TPMKeyInventory,
		IssuerHierarchy:       c.config.Authority.IssuerHierarchy,
	}
}

func (c *Coordinator) dexRequest() DexRequest {
	return DexRequest{
		Artifact:         c.config.Artifacts.Dex,
		IssuerHierarchy:  c.config.Authority.IssuerHierarchy,
		IngressTokenFlow: c.config.Authority.IngressTokenFlow,
	}
}

func (c *Coordinator) now() (time.Time, error) {
	now := c.clock.Now().UTC()
	if now.IsZero() {
		return time.Time{}, errors.New("bootstrap clock returned a zero time")
	}
	return now, nil
}

func evidenceOf(observation Observation) Evidence {
	return Evidence{Observations: []Observation{observation}}
}

func randomTransactionID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}

type recordVerificationError struct {
	step Step
	err  error
}

func (e *recordVerificationError) Error() string {
	return fmt.Sprintf("step %q: %v", e.step, e.err)
}

func (e *recordVerificationError) Unwrap() error {
	return e.err
}

func verificationFailureStep(journal Journal, err error) Step {
	var verificationError *recordVerificationError
	if errors.As(err, &verificationError) {
		return verificationError.step
	}
	if journal.Current != nil {
		return journal.Current.Step
	}
	if len(journal.Steps) < len(orderedSteps) {
		return orderedSteps[len(journal.Steps)]
	}
	return StepMarkComplete
}
