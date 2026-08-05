// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package ipfs

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/ipfs/go-cid"

	"github.com/sovereignite/sovereignite/internal/trust"
)

var (
	// ErrTrustRevisionRollback means a publication predates Trust state that
	// has already been durably reserved or completed.
	ErrTrustRevisionRollback = errors.New(
		"Trust publication state revision would roll back public state",
	)
	// ErrTrustRevisionConflict means different content claims the same
	// authoritative Trust state revision.
	ErrTrustRevisionConflict = errors.New(
		"Trust publication state revision conflicts with durable public state",
	)
)

// Clock makes record freshness and expiry behavior deterministic in tests.
type Clock interface {
	Now() time.Time
}

type wallClock struct{}

func (wallClock) Now() time.Time {
	return time.Now()
}

// Publisher consumes Trust's durable public-only outbox items. It owns the
// complete import/inspection/pin/sign/publish transaction and monotonic IPNS
// publication state.
type Publisher struct {
	mu     sync.Mutex
	node   FullKuboNode
	signer *TPMIPNSSigner
	store  PublicationStateStore
	policy RecordPolicy
	clock  Clock
}

// NewPublisher creates the public publication transaction boundary.
func NewPublisher(
	node FullKuboNode,
	signer *TPMIPNSSigner,
	store PublicationStateStore,
	policy RecordPolicy,
	clock Clock,
) (*Publisher, error) {
	if isNil(node) {
		return nil, errors.New("full Kubo node is required")
	}
	if signer == nil {
		return nil, errors.New("TPM IPNS signer is required")
	}
	if isNil(store) {
		return nil, errors.New("IPFS publication state store is required")
	}
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	if isNil(clock) {
		clock = wallClock{}
	}
	return &Publisher{
		node:   node,
		signer: signer,
		store:  store,
		policy: policy,
		clock:  clock,
	}, nil
}

// Publish implements trust.Publisher. It does not advance IPNS until the
// complete reachable DAG has been inspected, content-address verified, and
// pinned. Any failure retains the previous completed root.
func (p *Publisher) Publish(
	ctx context.Context,
	publication trust.Publication,
) (trust.PublicationReceipt, error) {
	if p == nil {
		return trust.PublicationReceipt{}, errors.New(
			"IPFS publisher is required",
		)
	}
	if isNil(ctx) {
		return trust.PublicationReceipt{}, errors.New(
			"publication context is required",
		)
	}
	if err := ctx.Err(); err != nil {
		return trust.PublicationReceipt{}, err
	}
	if err := publication.Validate(); err != nil {
		return trust.PublicationReceipt{}, fmt.Errorf(
			"validate Trust public publication: %w",
			err,
		)
	}
	snapshot, err := NewPublicSnapshot(publication, p.signer.Name())
	if err != nil {
		return trust.PublicationReceipt{}, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return trust.PublicationReceipt{}, err
	}
	state, err := p.store.Load()
	if err != nil {
		return trust.PublicationReceipt{}, fmt.Errorf(
			"load durable IPFS publication state: %w",
			err,
		)
	}
	if err := p.validateStateForSigner(state); err != nil {
		return trust.PublicationReceipt{}, err
	}
	if err := validateSnapshotRevision(state, snapshot); err != nil {
		return trust.PublicationReceipt{}, err
	}
	if completedPublicationMatches(state, snapshot) {
		root, err := canonicalRootCID(state.LastRootCID)
		if err != nil {
			return trust.PublicationReceipt{}, err
		}
		previousSequence := state.LastSequence - 1
		if err := ValidateSignedRecord(
			*state.LastRecord,
			RecordValidation{
				ExpectedName:     p.signer.Name(),
				ExpectedRoot:     root,
				PreviousSequence: previousSequence,
				Now:              p.clock.Now(),
				Policy:           p.policy,
				PublicKey:        p.signer.GetPublic(),
			},
		); err != nil {
			return trust.PublicationReceipt{}, fmt.Errorf(
				"validate completed IPNS record freshness: %w",
				err,
			)
		}
		if err := p.inspectAndPin(ctx, snapshot, root); err != nil {
			return trust.PublicationReceipt{}, err
		}
		return completedReceipt(state), nil
	}

	if state.Pending != nil {
		if !pendingPublicationMatches(*state.Pending, snapshot) {
			return trust.PublicationReceipt{}, ErrPublicationPending
		}
		root, err := canonicalRootCID(state.Pending.RootCID)
		if err != nil {
			return trust.PublicationReceipt{}, err
		}
		if err := p.inspectAndPin(ctx, snapshot, root); err != nil {
			return trust.PublicationReceipt{}, err
		}
		prepared := state
		if p.recordNeedsRefresh(state.Pending.Record) {
			prepared, err = p.prepareRecord(
				ctx,
				state,
				snapshot,
				root,
			)
			if err != nil {
				return trust.PublicationReceipt{}, err
			}
		}
		return p.publishPrepared(ctx, prepared, snapshot)
	}

	imported, err := p.node.ImportPublicSnapshot(ctx, snapshot)
	if err != nil {
		return trust.PublicationReceipt{}, fmt.Errorf(
			"import complete public snapshot into Kubo: %w",
			err,
		)
	}
	if err := p.inspectAndPin(ctx, snapshot, imported.Root); err != nil {
		return trust.PublicationReceipt{}, err
	}
	prepared, err := p.prepareRecord(
		ctx,
		state,
		snapshot,
		imported.Root,
	)
	if err != nil {
		return trust.PublicationReceipt{}, err
	}
	return p.publishPrepared(ctx, prepared, snapshot)
}

func (p *Publisher) inspectAndPin(
	ctx context.Context,
	snapshot PublicSnapshot,
	root cid.Cid,
) error {
	if !root.Defined() || root.Version() != 1 {
		return errors.New("Kubo import returned an invalid root CID")
	}
	inspection, err := p.node.InspectPublicSnapshot(ctx, root)
	if err != nil {
		return fmt.Errorf("inspect complete reachable public DAG: %w", err)
	}
	if err := validateImportedSnapshot(
		ImportedSnapshot{Root: root},
		snapshot,
		inspection,
	); err != nil {
		return fmt.Errorf("validate complete reachable public DAG: %w", err)
	}
	if err := p.node.PinPublicSnapshot(ctx, root); err != nil {
		return fmt.Errorf("pin complete public snapshot: %w", err)
	}
	pinned, err := p.node.PublicSnapshotPinned(ctx, root)
	if err != nil {
		return fmt.Errorf("verify public snapshot pin: %w", err)
	}
	if !pinned {
		return errors.New("Kubo did not retain the complete snapshot pin")
	}
	return nil
}

func (p *Publisher) prepareRecord(
	ctx context.Context,
	current PublicationState,
	snapshot PublicSnapshot,
	root cid.Cid,
) (PublicationState, error) {
	if current.HighSequence == math.MaxUint64 {
		return PublicationState{}, errors.New(
			"IPNS sequence high-water mark is exhausted",
		)
	}
	if current.Revision == math.MaxUint64 {
		return PublicationState{}, errors.New(
			"IPFS publication state revision is exhausted",
		)
	}
	sequence := current.HighSequence + 1
	record, err := CreateSignedRecord(
		ctx,
		p.signer,
		root,
		sequence,
		p.clock.Now(),
		p.policy,
	)
	if err != nil {
		return PublicationState{}, err
	}
	next := current.Clone()
	next.Revision++
	next.IPNSName = p.signer.Name()
	next.HighSequence = sequence
	next.Pending = &PendingPublication{
		PublicationID: snapshot.PublicationID(),
		Digest:        snapshot.Digest(),
		TrustRevision: snapshot.StateRevision(),
		RootCID:       root.String(),
		Record:        record.Clone(),
	}
	if err := validatePublicationState(next); err != nil {
		return PublicationState{}, err
	}
	if err := p.store.Commit(current.Revision, next); err != nil {
		return PublicationState{}, fmt.Errorf(
			"durably prepare monotonic IPNS record: %w",
			err,
		)
	}
	return next, nil
}

func (p *Publisher) publishPrepared(
	ctx context.Context,
	prepared PublicationState,
	snapshot PublicSnapshot,
) (trust.PublicationReceipt, error) {
	if prepared.Pending == nil ||
		!pendingPublicationMatches(*prepared.Pending, snapshot) {
		return trust.PublicationReceipt{}, errors.New(
			"durably prepared IPNS record does not match publication",
		)
	}
	if prepared.Revision == math.MaxUint64 {
		return trust.PublicationReceipt{}, errors.New(
			"IPFS publication state revision is exhausted",
		)
	}
	root, err := canonicalRootCID(prepared.Pending.RootCID)
	if err != nil {
		return trust.PublicationReceipt{}, err
	}
	var previousIssuedAt time.Time
	if prepared.LastRecord != nil {
		previousIssuedAt = prepared.LastRecord.IssuedAt
	}
	if err := ValidateSignedRecord(
		prepared.Pending.Record,
		RecordValidation{
			ExpectedName:     p.signer.Name(),
			ExpectedRoot:     root,
			PreviousSequence: prepared.LastSequence,
			PreviousIssuedAt: previousIssuedAt,
			Now:              p.clock.Now(),
			Policy:           p.policy,
			PublicKey:        p.signer.GetPublic(),
		},
	); err != nil {
		return trust.PublicationReceipt{}, fmt.Errorf(
			"validate prepared IPNS record: %w",
			err,
		)
	}
	if err := p.node.PublishSignedRecord(
		ctx,
		prepared.Pending.Record.Clone(),
	); err != nil {
		return trust.PublicationReceipt{}, fmt.Errorf(
			"publish pre-signed IPNS record: %w",
			err,
		)
	}

	completed := prepared.Clone()
	completed.Revision++
	completed.LastSequence = prepared.Pending.Record.Sequence
	completed.LastPublicationID = prepared.Pending.PublicationID
	completed.LastDigest = prepared.Pending.Digest
	completed.LastTrustRevision = prepared.Pending.TrustRevision
	completed.LastRootCID = prepared.Pending.RootCID
	record := prepared.Pending.Record.Clone()
	completed.LastRecord = &record
	completed.Pending = nil
	if err := validatePublicationState(completed); err != nil {
		return trust.PublicationReceipt{}, err
	}
	if err := p.store.Commit(prepared.Revision, completed); err != nil {
		return trust.PublicationReceipt{}, fmt.Errorf(
			"commit published IPNS record: %w",
			err,
		)
	}
	return completedReceipt(completed), nil
}

func (p *Publisher) validateStateForSigner(
	state PublicationState,
) error {
	if err := validatePublicationState(state); err != nil {
		return fmt.Errorf("validate durable IPFS publication state: %w", err)
	}
	if state.IPNSName != "" && state.IPNSName != p.signer.Name() {
		return errors.New(
			"durable IPFS publication state belongs to another IPNS identity",
		)
	}
	if state.LastRecord != nil {
		root, err := canonicalRootCID(state.LastRootCID)
		if err != nil {
			return err
		}
		if err := verifyRecordBindingAndSignature(
			*state.LastRecord,
			p.signer.Name(),
			root,
			p.signer.GetPublic(),
		); err != nil {
			return fmt.Errorf(
				"verify last durable IPNS record: %w",
				err,
			)
		}
	}
	if state.Pending != nil {
		root, err := canonicalRootCID(state.Pending.RootCID)
		if err != nil {
			return err
		}
		if err := verifyRecordBindingAndSignature(
			state.Pending.Record,
			p.signer.Name(),
			root,
			p.signer.GetPublic(),
		); err != nil {
			return fmt.Errorf(
				"verify pending durable IPNS record: %w",
				err,
			)
		}
	}
	return nil
}

func (p *Publisher) recordNeedsRefresh(record SignedRecord) bool {
	now := p.clock.Now().UTC()
	return !record.ValidUntil.After(now) ||
		(now.After(record.IssuedAt) &&
			now.Sub(record.IssuedAt) > p.policy.MaxStaleness) ||
		record.ValidUntil.Sub(record.IssuedAt) > p.policy.MaxValidity
}

func completedPublicationMatches(
	state PublicationState,
	snapshot PublicSnapshot,
) bool {
	return state.Pending == nil &&
		state.LastSequence != 0 &&
		state.LastTrustRevision == snapshot.StateRevision() &&
		state.LastPublicationID == snapshot.PublicationID() &&
		state.LastDigest == snapshot.Digest()
}

func pendingPublicationMatches(
	pending PendingPublication,
	snapshot PublicSnapshot,
) bool {
	return pending.TrustRevision == snapshot.StateRevision() &&
		pending.PublicationID == snapshot.PublicationID() &&
		pending.Digest == snapshot.Digest()
}

func validateSnapshotRevision(
	state PublicationState,
	snapshot PublicSnapshot,
) error {
	revision := snapshot.StateRevision()
	if revision < state.LastTrustRevision {
		return fmt.Errorf(
			"%w: input=%d completed=%d",
			ErrTrustRevisionRollback,
			revision,
			state.LastTrustRevision,
		)
	}
	if revision == state.LastTrustRevision &&
		state.LastTrustRevision != 0 &&
		(state.LastPublicationID != snapshot.PublicationID() ||
			state.LastDigest != snapshot.Digest()) {
		return fmt.Errorf(
			"%w: revision %d differs from completed digest",
			ErrTrustRevisionConflict,
			revision,
		)
	}
	if state.Pending == nil {
		return nil
	}
	if revision < state.Pending.TrustRevision {
		return fmt.Errorf(
			"%w: input=%d pending=%d",
			ErrTrustRevisionRollback,
			revision,
			state.Pending.TrustRevision,
		)
	}
	if revision == state.Pending.TrustRevision &&
		(state.Pending.PublicationID != snapshot.PublicationID() ||
			state.Pending.Digest != snapshot.Digest()) {
		return fmt.Errorf(
			"%w: revision %d differs from pending digest",
			ErrTrustRevisionConflict,
			revision,
		)
	}
	return nil
}

func completedReceipt(state PublicationState) trust.PublicationReceipt {
	return trust.PublicationReceipt{
		PublicationID: state.LastPublicationID,
		Digest:        state.LastDigest,
		IPNSName:      state.IPNSName,
		RootCID:       state.LastRootCID,
		IPNSSequence:  state.LastSequence,
	}
}

var _ trust.Publisher = (*Publisher)(nil)
