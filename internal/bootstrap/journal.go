// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package bootstrap

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"syscall"
	"time"
)

const maximumJournalBytes = 4 << 20

var (
	// ErrJournalConflict means another writer advanced the journal revision.
	ErrJournalConflict = errors.New("bootstrap journal revision conflict")
	// ErrJournalDurabilityUncertain means atomic replacement became visible but
	// the containing-directory durability barrier failed.
	ErrJournalDurabilityUncertain = errors.New(
		"bootstrap journal durability is uncertain",
	)
)

var journalProcessLocks sync.Map

// JournalState is the durable lifecycle state.
type JournalState string

const (
	JournalInProgress JournalState = "in_progress"
	JournalComplete   JournalState = "complete"
	JournalFailed     JournalState = "failed"
)

// Attempt is a durable intent to execute the next uncommitted step.
type Attempt struct {
	Step      Step      `json:"step"`
	StartedAt time.Time `json:"started_at"`
	Attempts  uint64    `json:"attempts"`
}

// StepRecord is the durable result of one verified step.
type StepRecord struct {
	Step        Step      `json:"step"`
	Evidence    Evidence  `json:"evidence"`
	CompletedAt time.Time `json:"completed_at"`
}

// Failure is deliberately sanitized before persistence.
type Failure struct {
	Step    Step      `json:"step"`
	Code    string    `json:"code"`
	Message string    `json:"message"`
	At      time.Time `json:"at"`
}

const (
	failureAction       = "step_action_failed"
	failureVerification = "step_verification_failed"
	failurePrepared     = "prepared_readiness_failed"
)

// Journal is the complete versioned durable bootstrap transaction. It stores
// evidence hashes and public observations only, never artifact bytes, keys,
// kubeconfigs, certificates, tokens, or cluster secrets.
type Journal struct {
	Version             uint32       `json:"version"`
	Revision            uint64       `json:"revision"`
	TransactionID       string       `json:"transaction_id"`
	BootstrapVersion    string       `json:"bootstrap_version"`
	ConfigurationSHA256 string       `json:"configuration_sha256"`
	State               JournalState `json:"state"`
	Prepared            bool         `json:"prepared"`
	PreparedAt          *time.Time   `json:"prepared_at,omitempty"`
	Steps               []StepRecord `json:"steps"`
	Current             *Attempt     `json:"current,omitempty"`
	Failure             *Failure     `json:"failure,omitempty"`
	UpdatedAt           time.Time    `json:"updated_at"`
}

// JournalStore provides revision-checked durable commits. A zero Journal from
// Load means no transaction has ever been persisted.
type JournalStore interface {
	Load() (Journal, error)
	Save(expectedRevision uint64, next Journal) error
}

// FileJournalStore atomically replaces one owner-only journal document.
type FileJournalStore struct {
	path     string
	lockPath string
}

// NewFileJournalStore creates a journal store at an absolute resolved path.
func NewFileJournalStore(path string) (*FileJournalStore, error) {
	if path == "" {
		return nil, errors.New("bootstrap journal path is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve bootstrap journal path: %w", err)
	}
	return &FileJournalStore{
		path:     absolute,
		lockPath: absolute + ".lock",
	}, nil
}

// Load strictly decodes the current journal. Missing state is returned as the
// zero Journal; unknown or corrupt state is never reset.
func (s *FileJournalStore) Load() (Journal, error) {
	if s == nil || s.path == "" {
		return Journal{}, errors.New("bootstrap journal store is not configured")
	}
	if err := ensurePrivateDirectory(filepath.Dir(s.path)); err != nil {
		return Journal{}, err
	}
	processLock := journalProcessLock(s.lockPath)
	processLock.Lock()
	defer processLock.Unlock()
	lock, err := acquireJournalLock(s.lockPath, syscall.LOCK_SH)
	if err != nil {
		return Journal{}, err
	}
	defer releaseJournalLock(lock)
	journal, exists, err := loadJournalFile(s.path)
	if err != nil {
		return Journal{}, err
	}
	if !exists {
		return Journal{}, nil
	}
	return cloneJournal(journal), nil
}

// Save writes, syncs, atomically renames, and directory-syncs a complete next
// revision. It refuses stale writers.
func (s *FileJournalStore) Save(expectedRevision uint64, next Journal) error {
	if s == nil || s.path == "" {
		return errors.New("bootstrap journal store is not configured")
	}
	if next.Revision != expectedRevision+1 {
		return fmt.Errorf(
			"next journal revision %d, expected %d",
			next.Revision,
			expectedRevision+1,
		)
	}
	if err := validateJournal(next); err != nil {
		return err
	}
	directory := filepath.Dir(s.path)
	if err := ensurePrivateDirectory(directory); err != nil {
		return err
	}
	processLock := journalProcessLock(s.lockPath)
	processLock.Lock()
	defer processLock.Unlock()
	lock, err := acquireJournalLock(s.lockPath, syscall.LOCK_EX)
	if err != nil {
		return err
	}
	defer releaseJournalLock(lock)
	current, exists, err := loadJournalFile(s.path)
	if err != nil {
		return err
	}
	currentRevision := uint64(0)
	if exists {
		currentRevision = current.Revision
	}
	if currentRevision != expectedRevision {
		return fmt.Errorf(
			"%w: current revision %d, expected %d",
			ErrJournalConflict,
			currentRevision,
			expectedRevision,
		)
	}

	encoded, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return fmt.Errorf("encode bootstrap journal: %w", err)
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maximumJournalBytes {
		return fmt.Errorf(
			"encoded bootstrap journal is %d bytes, limit is %d",
			len(encoded),
			maximumJournalBytes,
		)
	}

	temporary, err := os.CreateTemp(
		directory,
		"."+filepath.Base(s.path)+".tmp-*",
	)
	if err != nil {
		return fmt.Errorf("create bootstrap journal temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()

	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("set bootstrap journal permissions: %w", err)
	}
	if _, err := io.Copy(temporary, bytes.NewReader(encoded)); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write bootstrap journal: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync bootstrap journal: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close bootstrap journal: %w", err)
	}
	if err := os.Rename(temporaryPath, s.path); err != nil {
		return fmt.Errorf("replace bootstrap journal: %w", err)
	}
	directoryFile, err := os.Open(directory)
	if err != nil {
		return errors.Join(
			ErrJournalDurabilityUncertain,
			fmt.Errorf("open bootstrap journal directory for sync: %w", err),
		)
	}
	syncErr := directoryFile.Sync()
	closeErr := directoryFile.Close()
	if syncErr != nil {
		return errors.Join(
			ErrJournalDurabilityUncertain,
			fmt.Errorf("sync bootstrap journal directory: %w", syncErr),
		)
	}
	if closeErr != nil {
		return errors.Join(
			ErrJournalDurabilityUncertain,
			fmt.Errorf("close bootstrap journal directory: %w", closeErr),
		)
	}
	return nil
}

func loadJournalFile(path string) (Journal, bool, error) {
	info, err := secureRegularFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Journal{}, false, nil
	}
	if err != nil {
		return Journal{}, false, err
	}
	if info.Size() <= 0 || info.Size() > maximumJournalBytes {
		return Journal{}, false, fmt.Errorf(
			"bootstrap journal size %d is outside 1..%d",
			info.Size(),
			maximumJournalBytes,
		)
	}
	file, err := os.Open(path)
	if err != nil {
		return Journal{}, false, fmt.Errorf("open bootstrap journal: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()
	openedInfo, err := file.Stat()
	if err != nil {
		return Journal{}, false, fmt.Errorf("stat opened bootstrap journal: %w", err)
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return Journal{}, false, errors.New(
			"bootstrap journal changed while opening",
		)
	}

	decoder := json.NewDecoder(io.LimitReader(file, maximumJournalBytes+1))
	decoder.DisallowUnknownFields()
	var journal Journal
	if err := decoder.Decode(&journal); err != nil {
		return Journal{}, false, fmt.Errorf("decode bootstrap journal: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return Journal{}, false, errors.New(
				"bootstrap journal contains multiple JSON values",
			)
		}
		return Journal{}, false, fmt.Errorf(
			"decode trailing bootstrap journal data: %w",
			err,
		)
	}
	if err := validateJournal(journal); err != nil {
		return Journal{}, false, err
	}
	return journal, true, nil
}

func validateJournal(journal Journal) error {
	if journal.Version != JournalVersion {
		return fmt.Errorf(
			"unsupported bootstrap journal version %d, expected %d",
			journal.Version,
			JournalVersion,
		)
	}
	if journal.Revision == 0 {
		return errors.New("bootstrap journal revision must be positive")
	}
	if !validTransactionID(journal.TransactionID) {
		return errors.New("bootstrap journal transaction ID is invalid")
	}
	if err := validatePinnedIdentifier(
		"journal bootstrap version",
		journal.BootstrapVersion,
	); err != nil {
		return err
	}
	if !validSHA256(journal.ConfigurationSHA256) {
		return errors.New("bootstrap journal configuration digest is invalid")
	}
	if journal.UpdatedAt.IsZero() || journal.UpdatedAt.Location() != time.UTC {
		return errors.New("bootstrap journal update time must be nonzero UTC")
	}
	if len(journal.Steps) > len(orderedSteps) {
		return errors.New("bootstrap journal contains more than nine steps")
	}
	for index, record := range journal.Steps {
		if record.Step != orderedSteps[index] {
			return fmt.Errorf(
				"bootstrap journal step %d is %q, expected %q",
				index+1,
				record.Step,
				orderedSteps[index],
			)
		}
		if record.CompletedAt.IsZero() ||
			record.CompletedAt.Location() != time.UTC ||
			record.CompletedAt.After(journal.UpdatedAt) {
			return fmt.Errorf("bootstrap journal step %q has an invalid completion time", record.Step)
		}
		if err := validateEvidenceShape(record.Step, record.Evidence); err != nil {
			return fmt.Errorf("bootstrap journal step %q evidence: %w", record.Step, err)
		}
	}

	shouldBePrepared := len(journal.Steps) >= stepIndex(StepSPIRETPMConfig)+1
	if journal.Prepared != shouldBePrepared {
		return errors.New(
			"bootstrap journal prepared state does not match completed prerequisites",
		)
	}
	if journal.Prepared {
		if journal.PreparedAt == nil ||
			journal.PreparedAt.IsZero() ||
			journal.PreparedAt.Location() != time.UTC ||
			journal.PreparedAt.After(journal.UpdatedAt) {
			return errors.New("bootstrap journal prepared time is invalid")
		}
	} else if journal.PreparedAt != nil {
		return errors.New("bootstrap journal has a prepared time while not prepared")
	}

	switch journal.State {
	case JournalInProgress:
		if journal.Failure != nil {
			return errors.New("in-progress bootstrap journal contains a failure")
		}
		if len(journal.Steps) == len(orderedSteps) {
			return errors.New("in-progress bootstrap journal already contains all steps")
		}
	case JournalComplete:
		if len(journal.Steps) != len(orderedSteps) ||
			journal.Current != nil ||
			journal.Failure != nil ||
			!journal.Prepared {
			return errors.New("complete bootstrap journal is not fully verified")
		}
	case JournalFailed:
		if journal.Failure == nil {
			return errors.New("failed bootstrap journal has no failure record")
		}
	default:
		return fmt.Errorf("unknown bootstrap journal state %q", journal.State)
	}

	if journal.Current != nil {
		if len(journal.Steps) == len(orderedSteps) ||
			journal.Current.Step != orderedSteps[len(journal.Steps)] {
			return errors.New("bootstrap journal current step is not the next step")
		}
		if journal.Current.Attempts == 0 ||
			journal.Current.StartedAt.IsZero() ||
			journal.Current.StartedAt.Location() != time.UTC ||
			journal.Current.StartedAt.After(journal.UpdatedAt) {
			return errors.New("bootstrap journal current attempt is invalid")
		}
	}
	if journal.Failure != nil {
		if stepIndex(journal.Failure.Step) < 0 ||
			journal.Failure.At.IsZero() ||
			journal.Failure.At.Location() != time.UTC ||
			journal.Failure.At.After(journal.UpdatedAt) {
			return errors.New("bootstrap journal failure is invalid")
		}
		switch journal.Failure.Code {
		case failureAction, failureVerification, failurePrepared:
		default:
			return errors.New("bootstrap journal failure code is invalid")
		}
		if journal.Failure.Message != failureMessage(
			journal.Failure.Step,
			journal.Failure.Code,
		) {
			return errors.New("bootstrap journal failure message is not sanitized")
		}
	}
	return nil
}

func validateEvidenceShape(step Step, evidence Evidence) error {
	expected := expectedComponents(step)
	if len(evidence.Observations) != len(expected) {
		return fmt.Errorf(
			"contains %d observations, expected %d",
			len(evidence.Observations),
			len(expected),
		)
	}
	for index, observation := range evidence.Observations {
		if observation.Component != expected[index] {
			return fmt.Errorf(
				"observation %d is for %q, expected %q",
				index+1,
				observation.Component,
				expected[index],
			)
		}
		if err := validatePinnedIdentifier(
			"observation version",
			observation.Version,
		); err != nil {
			return err
		}
		if !validSHA256(observation.ArtifactSHA256) ||
			!validSHA256(observation.ResourceSHA256) {
			return errors.New("observation digest is not canonical SHA-256")
		}
		if (step == StepWaitControlPlane ||
			step == StepApplyClusterConfigs ||
			step == StepMarkComplete) &&
			!observation.Ready {
			return errors.New("readiness step contains a non-ready observation")
		}
	}
	return nil
}

func expectedComponents(step Step) []Component {
	switch step {
	case StepTPMKeyManagerCASigning:
		return []Component{ComponentKeyManager}
	case StepKubeletConfig, StepInitializeAPIServer, StepWaitControlPlane:
		return []Component{ComponentKubernetes}
	case StepCalicoIPv6:
		return []Component{ComponentCalico}
	case StepIstioIngress:
		return []Component{ComponentIstio}
	case StepSPIRETPMConfig:
		return []Component{ComponentSPIRE}
	case StepApplyClusterConfigs, StepMarkComplete:
		return []Component{
			ComponentKubernetes,
			ComponentCalico,
			ComponentIstio,
			ComponentSPIRE,
			ComponentDex,
		}
	default:
		return nil
	}
}

func failureMessage(step Step, code string) string {
	switch code {
	case failureVerification:
		return fmt.Sprintf("%s verification failed; existing state was preserved", step)
	case failurePrepared:
		return fmt.Sprintf("%s completed but prepared readiness publication failed", step)
	default:
		return fmt.Sprintf("%s failed; existing state was preserved", step)
	}
}

func cloneJournal(journal Journal) Journal {
	journal.Steps = slices.Clone(journal.Steps)
	for index := range journal.Steps {
		journal.Steps[index].Evidence.Observations = slices.Clone(
			journal.Steps[index].Evidence.Observations,
		)
	}
	if journal.Current != nil {
		current := *journal.Current
		journal.Current = &current
	}
	if journal.Failure != nil {
		failure := *journal.Failure
		journal.Failure = &failure
	}
	if journal.PreparedAt != nil {
		preparedAt := *journal.PreparedAt
		journal.PreparedAt = &preparedAt
	}
	return journal
}

func ensurePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return errors.New(
			"bootstrap state directory must be provisioned before service start",
		)
	}
	if err != nil {
		return fmt.Errorf("inspect bootstrap state directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("bootstrap state parent is not a real directory")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf(
			"bootstrap state directory permissions %04o allow group or other access",
			info.Mode().Perm(),
		)
	}
	return nil
}

func secureRegularFile(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("bootstrap state path is not a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf(
			"bootstrap state file permissions %04o allow group or other access",
			info.Mode().Perm(),
		)
	}
	return info, nil
}

func acquireJournalLock(path string, operation int) (*os.File, error) {
	fileDescriptor, err := syscall.Open(
		path,
		syscall.O_CREAT|
			syscall.O_RDWR|
			syscall.O_CLOEXEC|
			syscall.O_NOFOLLOW,
		0o600,
	)
	if err != nil {
		return nil, fmt.Errorf("open bootstrap journal lock: %w", err)
	}
	file := os.NewFile(uintptr(fileDescriptor), path)
	if file == nil {
		_ = syscall.Close(fileDescriptor)
		return nil, errors.New("wrap bootstrap journal lock file descriptor")
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("inspect bootstrap journal lock: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		_ = file.Close()
		return nil, errors.New(
			"bootstrap journal lock must be a regular owner-only file",
		)
	}
	if err := syscall.Flock(fileDescriptor, operation); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock bootstrap journal: %w", err)
	}
	return file, nil
}

func releaseJournalLock(file *os.File) {
	if file == nil {
		return
	}
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	_ = file.Close()
}

func journalProcessLock(path string) *sync.Mutex {
	value, _ := journalProcessLocks.LoadOrStore(path, &sync.Mutex{})
	return value.(*sync.Mutex)
}

func validTransactionID(value string) bool {
	if len(value) != 32 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 16
}
