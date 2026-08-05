// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package releaseworkflow

import (
	"context"
	"iter"
	"testing"

	"google.golang.org/adk/v2/model"
)

type fakeLLM struct{}

func (fakeLLM) Name() string { return "fake-release-model" }

func (fakeLLM) GenerateContent(context.Context, *model.LLMRequest, bool) iter.Seq2[*model.LLMResponse, error] {
	return func(func(*model.LLMResponse, error) bool) {}
}

func TestNewReleaseCoordinatorDefinesTicketAgents(t *testing.T) {
	t.Parallel()

	root, err := NewReleaseCoordinator(Config{Model: fakeLLM{}})
	if err != nil {
		t.Fatal(err)
	}
	if root.Name() != ReleaseCoordinatorName {
		t.Fatalf("root name = %q, want %q", root.Name(), ReleaseCoordinatorName)
	}
	for _, name := range []string{
		IssueIntakeAgentName,
		ImplementationAgentName,
		ValidationAgentName,
		ReviewAgentName,
		StatusHandoffAgentName,
		ImprovementReviewerAgentName,
	} {
		if root.FindSubAgent(name) == nil {
			t.Fatalf("missing subagent %q", name)
		}
	}
	for _, forbidden := range []string{"merge_agent", "branch_protection_bypass_agent", "custom_scheduler_agent", "custom_lane_runner_agent"} {
		if root.FindSubAgent(forbidden) != nil {
			t.Fatalf("unexpected forbidden subagent %q", forbidden)
		}
	}
}

func TestNewReleaseCoordinatorConsumesA2ARemoteWorkers(t *testing.T) {
	t.Parallel()

	root, err := NewReleaseCoordinator(Config{
		Model: fakeLLM{},
		RemoteWorkers: []RemoteWorker{{
			Name:            "remote_validation_worker",
			Description:     "Remote validation worker exposed over A2A.",
			AgentCardSource: "http://127.0.0.1:9000",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if root.FindSubAgent("remote_validation_worker") == nil {
		t.Fatal("missing A2A remote worker")
	}
}

func TestNewReleaseCoordinatorRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()

	if _, err := NewReleaseCoordinator(Config{}); err == nil {
		t.Fatal("missing model unexpectedly accepted")
	}
	if _, err := NewReleaseCoordinator(Config{
		Model: fakeLLM{},
		RemoteWorkers: []RemoteWorker{{
			Name:            ImplementationAgentName,
			AgentCardSource: "http://127.0.0.1:9000",
		}},
	}); err == nil {
		t.Fatal("duplicate remote worker name unexpectedly accepted")
	}
	if _, err := NewReleaseCoordinator(Config{
		Model: fakeLLM{},
		RemoteWorkers: []RemoteWorker{{
			Name: "remote_worker_without_card",
		}},
	}); err == nil {
		t.Fatal("remote worker without agent card source unexpectedly accepted")
	}
}

func TestStatusHandoffAndImprovementProposalResultsStayAuditable(t *testing.T) {
	t.Parallel()

	handoff, err := recordStatusHandoff(nil, StatusHandoffArgs{
		IssueNumber: 26,
		Summary:     "implemented ADK release workflow team",
		Validation:  "targeted tests passed",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !handoff.RequiresHumanApproval || handoff.Status != "ready_for_human_handoff" {
		t.Fatalf("handoff = %#v", handoff)
	}

	proposal, err := proposeFollowUpTask(nil, ImprovementProposalArgs{
		Evidence:          []string{"validation_agent reported a missing test category"},
		Defect:            "coverage gap",
		RecommendedChange: "add a narrow validation test proposal",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !proposal.RequiresNormalReviewedFlow || proposal.Status != "proposal_ready_for_human_review" {
		t.Fatalf("proposal = %#v", proposal)
	}
}

func TestNewHumanApprovalWorkflow(t *testing.T) {
	t.Parallel()

	approval, err := NewHumanApprovalWorkflow("", "")
	if err != nil {
		t.Fatal(err)
	}
	if approval.Name() != "release_human_approval_workflow" {
		t.Fatalf("approval workflow name = %q", approval.Name())
	}
}
