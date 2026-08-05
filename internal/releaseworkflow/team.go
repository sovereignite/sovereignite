// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

// Package releaseworkflow assembles the ADK/A2A agent team used to coordinate
// repository release tasks. The package intentionally does not start workers,
// allocate worktrees, run shells, or merge pull requests.
package releaseworkflow

import (
	"errors"
	"fmt"
	"strings"

	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/agent/llmagent"
	"google.golang.org/adk/v2/agent/remoteagent"
	"google.golang.org/adk/v2/agent/workflowagent"
	"google.golang.org/adk/v2/model"
	"google.golang.org/adk/v2/session"
	"google.golang.org/adk/v2/tool"
	"google.golang.org/adk/v2/tool/functiontool"
	"google.golang.org/adk/v2/workflow"
)

const (
	ReleaseCoordinatorName       = "release_coordinator"
	IssueIntakeAgentName         = "issue_intake_agent"
	ImplementationAgentName      = "implementation_agent"
	ValidationAgentName          = "validation_agent"
	ReviewAgentName              = "review_agent"
	StatusHandoffAgentName       = "status_handoff_agent"
	ImprovementReviewerAgentName = "improvement_reviewer_agent"
)

type roleSpec struct {
	name        string
	description string
	mode        llmagent.Mode
	instruction string
}

var roleSpecs = []roleSpec{
	{
		name:        IssueIntakeAgentName,
		description: "Reads assigned GitHub tasks and extracts constraints, acceptance criteria, open questions, and expected outputs.",
		mode:        llmagent.ModeTask,
		instruction: strings.TrimSpace(`
Read only the assigned GitHub task context exposed through your tools.
Extract constraints, acceptance criteria, open questions, expected outputs, and task boundaries.
Ask clarifying questions only when required to avoid violating the task scope, then call finish_task with a concise intake report.
Do not modify branches, pull requests, workflow definitions, or repository files.
Do not call shell commands or orchestrate external executables.
Do not merge pull requests, approve your own work, bypass branch protection, or request authority to do so.`),
	},
	{
		name:        ImplementationAgentName,
		description: "Performs scoped implementation work using only exposed ADK tools, MCP toolsets, A2A agents, in-process functions, or direct APIs.",
		mode:        llmagent.ModeSingleTurn,
		instruction: strings.TrimSpace(`
Implement only the assigned task and only through the tools explicitly exposed to this role.
Use ADK tools, MCP toolsets, A2A agents, in-process functions, or direct API integrations when available.
Do not call shell commands or orchestrate external executables from agent code.
Do not allocate worktrees, manage containers, build images, mount filesystems, or operate host infrastructure.
Do not merge pull requests, bypass branch protection, push to protected branches, or grant yourself new tools.
Return evidence describing what changed and how it remains within task scope.`),
	},
	{
		name:        ValidationAgentName,
		description: "Validates work through approved ADK tools, MCP toolsets, A2A agents, or direct API integrations and reports results.",
		mode:        llmagent.ModeSingleTurn,
		instruction: strings.TrimSpace(`
Validate only the assigned work using tools exposed to this role.
Report commands, APIs, tool calls, outcomes, failures, and blockers exactly.
Do not call shell commands or external executables from agent code; validation execution must come from approved ADK tools, MCP toolsets, A2A agents, or direct APIs.
Do not fix adjacent findings, mutate branch protection, approve pull requests, or merge pull requests.`),
	},
	{
		name:        ReviewAgentName,
		description: "Reviews changes against the issue, regressions, missing tests, risks, and policy boundaries.",
		mode:        llmagent.ModeSingleTurn,
		instruction: strings.TrimSpace(`
Review the completed task against the issue requirements, repository policy, regressions, missing tests, and residual risks.
Prioritize correctness, security, scope control, and evidence quality.
You may comment through exposed review tools when appropriate, but final approval and merge remain human-controlled.
Do not call shell commands or external executables from agent code.
Do not approve pull requests, merge pull requests, bypass branch protection, or request tools that allow those actions.`),
	},
	{
		name:        StatusHandoffAgentName,
		description: "Summarizes outcomes, validation, residual risks, and comments on tasks or PRs when appropriate.",
		mode:        llmagent.ModeSingleTurn,
		instruction: strings.TrimSpace(`
Prepare an explicit status handoff from the collected intake, implementation, validation, and review evidence.
Use the record_status_handoff tool to format a handoff record before any exposed GitHub commenting tool is used.
Comment on tasks or pull requests only through tools exposed to this role and only when appropriate for status handoff.
Do not call shell commands or external executables from agent code.
Do not approve pull requests, merge pull requests, bypass branch protection, or treat handoff as final human approval.`),
	},
	{
		name:        ImprovementReviewerAgentName,
		description: "Reviews completed runs and proposes evidence-backed workflow, tooling, prompt, or evaluation improvements as tracked follow-up tasks.",
		mode:        llmagent.ModeSingleTurn,
		instruction: strings.TrimSpace(`
Review the completed run for defects in prompts, tools, workflows, evaluations, and handoffs.
Use propose_follow_up_task for any recursive self-improvement proposal. Include evidence from the run and one narrow recommended change.
Never silently rewrite instructions, tools, permissions, workflows, or evaluation criteria.
Self-improvement changes must go through normal issue, branch, pull request, validation, and human review flow.
Do not call shell commands or external executables from agent code.
Do not propose privilege escalation, branch-protection bypass, final approval, or merge authority.`),
	},
}

// Config describes the ADK root coordinator and its role-specific tool exposure.
type Config struct {
	Model model.LLM

	Capabilities  RoleCapabilities
	RemoteWorkers []RemoteWorker
}

// RoleCapabilities assigns tools and toolsets by job function. A caller may use
// ADK FunctionTools, MCP toolsets, A2A-backed agent tools, or direct API tools;
// this package does not translate them into a separate permission system.
type RoleCapabilities struct {
	Coordinator         AgentCapabilities
	IssueIntake         AgentCapabilities
	Implementation      AgentCapabilities
	Validation          AgentCapabilities
	Review              AgentCapabilities
	StatusHandoff       AgentCapabilities
	ImprovementReviewer AgentCapabilities
}

type AgentCapabilities struct {
	Tools    []tool.Tool
	Toolsets []tool.Toolset
}

// RemoteWorker is consumed through an A2A agent card. Use it for optional
// remote implementation, validation, or specialist agents when distribution or
// isolation is required by host infrastructure.
type RemoteWorker struct {
	Name            string
	Description     string
	AgentCardSource string
}

// NewReleaseCoordinator builds the ADK root coordinator with role-specific
// subagents. Declaring SubAgents lets ADK install delegation tools directly;
// task and single_turn modes are set on the role agents themselves.
func NewReleaseCoordinator(cfg Config) (agent.Agent, error) {
	if cfg.Model == nil {
		return nil, errors.New("release workflow model is required")
	}

	capabilities := cfg.Capabilities
	statusTool, err := newStatusHandoffTool()
	if err != nil {
		return nil, err
	}
	proposalTool, err := newImprovementProposalTool()
	if err != nil {
		return nil, err
	}
	capabilities.StatusHandoff.Tools = append([]tool.Tool{statusTool}, capabilities.StatusHandoff.Tools...)
	capabilities.ImprovementReviewer.Tools = append([]tool.Tool{proposalTool}, capabilities.ImprovementReviewer.Tools...)

	subAgents := make([]agent.Agent, 0, len(roleSpecs)+len(cfg.RemoteWorkers))
	seenNames := map[string]bool{ReleaseCoordinatorName: true}
	for _, spec := range roleSpecs {
		capability := capabilities.forRole(spec.name)
		roleAgent, err := llmagent.New(llmagent.Config{
			Name:                     spec.name,
			Description:              spec.description,
			Model:                    cfg.Model,
			Mode:                     spec.mode,
			Instruction:              spec.instruction,
			Tools:                    capability.Tools,
			Toolsets:                 capability.Toolsets,
			DisallowTransferToParent: true,
			DisallowTransferToPeers:  true,
		})
		if err != nil {
			return nil, fmt.Errorf("create %s: %w", spec.name, err)
		}
		seenNames[spec.name] = true
		subAgents = append(subAgents, roleAgent)
	}

	for _, worker := range cfg.RemoteWorkers {
		remoteAgent, err := newRemoteWorker(worker, seenNames)
		if err != nil {
			return nil, err
		}
		seenNames[worker.Name] = true
		subAgents = append(subAgents, remoteAgent)
	}

	return llmagent.New(llmagent.Config{
		Name:        ReleaseCoordinatorName,
		Description: "Root ADK coordinator for GitHub release tasks; delegates to role-specific agents and keeps human-controlled gates explicit.",
		Model:       cfg.Model,
		Instruction: releaseCoordinatorInstruction,
		SubAgents:   subAgents,
		Tools:       capabilities.Coordinator.Tools,
		Toolsets:    capabilities.Coordinator.Toolsets,
	})
}

func (c RoleCapabilities) forRole(name string) AgentCapabilities {
	switch name {
	case IssueIntakeAgentName:
		return c.IssueIntake
	case ImplementationAgentName:
		return c.Implementation
	case ValidationAgentName:
		return c.Validation
	case ReviewAgentName:
		return c.Review
	case StatusHandoffAgentName:
		return c.StatusHandoff
	case ImprovementReviewerAgentName:
		return c.ImprovementReviewer
	default:
		return AgentCapabilities{}
	}
}

func newRemoteWorker(worker RemoteWorker, seenNames map[string]bool) (agent.Agent, error) {
	name := strings.TrimSpace(worker.Name)
	if name == "" {
		return nil, errors.New("remote worker name is required")
	}
	if seenNames[name] {
		return nil, fmt.Errorf("agent name %q is already used", name)
	}
	source := strings.TrimSpace(worker.AgentCardSource)
	if source == "" {
		return nil, fmt.Errorf("remote worker %q agent card source is required", name)
	}
	description := strings.TrimSpace(worker.Description)
	if description == "" {
		description = "A2A remote worker agent for release task work."
	}
	return remoteagent.NewA2A(remoteagent.A2AConfig{
		Name:            name,
		Description:     description,
		AgentCardSource: source,
	})
}

var releaseCoordinatorInstruction = strings.TrimSpace(`
You are release_coordinator, the root ADK coordinator for one GitHub release task at a time.
Delegate by using the ADK-generated tools for role subagents instead of hardcoding lanes or scheduling your own workers.
Use issue_intake_agent for task constraints, implementation_agent for scoped implementation, validation_agent for validation, review_agent for review, status_handoff_agent for task or PR handoff, and improvement_reviewer_agent for auditable follow-up proposals.
Use task-mode agents when clarification is needed and single_turn agents for parallel-safe independent work.
Use graph HITL nodes or ADK tool confirmation for human approval gates. Final pull request approval and merge are always human-controlled.
Optional remote workers are normal A2A agents consumed from their agent cards; use them only when distribution or isolation is needed.
Tools exposed to role agents define their capabilities. Do not invent a scheduler, lane runner, delegate CLI, bespoke permission layer, or Nix-coupled harness.
Agents must not call shell commands or orchestrate external executables from agent code.
Container lifecycle, worktree allocation, image builds, mounts, credentials, and host process execution are host infrastructure concerns outside this agent team.
Never merge pull requests, bypass branch protection, push directly to protected branches, or grant any agent final approval authority.
Recursive self-improvement is limited to evidence-backed follow-up task proposals reviewed through normal issue, branch, pull request, validation, and human review flow.`)

type StatusHandoffArgs struct {
	IssueNumber   int    `json:"issue_number" jsonschema:"The GitHub issue number for the release task."`
	Summary       string `json:"summary" jsonschema:"Concise outcome summary."`
	Validation    string `json:"validation" jsonschema:"Validation performed and results."`
	ResidualRisks string `json:"residual_risks" jsonschema:"Residual risks or blockers, or 'none'."`
}

type StatusHandoffResult struct {
	Status                string `json:"status"`
	IssueNumber           int    `json:"issue_number"`
	Summary               string `json:"summary"`
	Validation            string `json:"validation"`
	ResidualRisks         string `json:"residual_risks"`
	RequiresHumanApproval bool   `json:"requires_human_approval"`
}

func newStatusHandoffTool() (tool.Tool, error) {
	return functiontool.New(functiontool.Config{
		Name:        "record_status_handoff",
		Description: "Formats release task status handoff evidence. It does not approve or merge pull requests.",
	}, recordStatusHandoff)
}

func recordStatusHandoff(_ agent.Context, args StatusHandoffArgs) (StatusHandoffResult, error) {
	if args.IssueNumber <= 0 {
		return StatusHandoffResult{}, errors.New("issue_number must be positive")
	}
	if strings.TrimSpace(args.Summary) == "" {
		return StatusHandoffResult{}, errors.New("summary is required")
	}
	if strings.TrimSpace(args.Validation) == "" {
		return StatusHandoffResult{}, errors.New("validation is required")
	}
	residualRisks := strings.TrimSpace(args.ResidualRisks)
	if residualRisks == "" {
		residualRisks = "none recorded"
	}
	return StatusHandoffResult{
		Status:                "ready_for_human_handoff",
		IssueNumber:           args.IssueNumber,
		Summary:               strings.TrimSpace(args.Summary),
		Validation:            strings.TrimSpace(args.Validation),
		ResidualRisks:         residualRisks,
		RequiresHumanApproval: true,
	}, nil
}

type ImprovementProposalArgs struct {
	Evidence          []string `json:"evidence" jsonschema:"Specific observations from the completed run that justify the proposal."`
	Defect            string   `json:"defect" jsonschema:"The workflow, tooling, prompt, or evaluation defect observed."`
	RecommendedChange string   `json:"recommended_change" jsonschema:"One narrow recommended change to review in a normal tracked task."`
}

type ImprovementProposalResult struct {
	Status                     string   `json:"status"`
	Evidence                   []string `json:"evidence"`
	Defect                     string   `json:"defect"`
	RecommendedChange          string   `json:"recommended_change"`
	RequiresNormalReviewedFlow bool     `json:"requires_normal_reviewed_flow"`
}

func newImprovementProposalTool() (tool.Tool, error) {
	return functiontool.New(functiontool.Config{
		Name:                "propose_follow_up_task",
		Description:         "Creates an auditable recursive self-improvement proposal. It does not modify agent behavior, tools, permissions, workflows, or evaluations.",
		RequireConfirmation: true,
	}, proposeFollowUpTask)
}

func proposeFollowUpTask(_ agent.Context, args ImprovementProposalArgs) (ImprovementProposalResult, error) {
	if len(args.Evidence) == 0 {
		return ImprovementProposalResult{}, errors.New("at least one evidence item is required")
	}
	defect := strings.TrimSpace(args.Defect)
	if defect == "" {
		return ImprovementProposalResult{}, errors.New("defect is required")
	}
	recommendedChange := strings.TrimSpace(args.RecommendedChange)
	if recommendedChange == "" {
		return ImprovementProposalResult{}, errors.New("recommended_change is required")
	}
	evidence := make([]string, 0, len(args.Evidence))
	for _, item := range args.Evidence {
		item = strings.TrimSpace(item)
		if item != "" {
			evidence = append(evidence, item)
		}
	}
	if len(evidence) == 0 {
		return ImprovementProposalResult{}, errors.New("at least one non-empty evidence item is required")
	}
	return ImprovementProposalResult{
		Status:                     "proposal_ready_for_human_review",
		Evidence:                   evidence,
		Defect:                     defect,
		RecommendedChange:          recommendedChange,
		RequiresNormalReviewedFlow: true,
	}, nil
}

type HumanApprovalResult struct {
	Status   string `json:"status"`
	Response string `json:"response"`
}

// NewHumanApprovalWorkflow creates a graph-backed HITL gate using ADK workflow
// primitives. The graph emits session.RequestInput and resumes after the human
// response; callers place this workflow before branch or PR mutation phases.
func NewHumanApprovalWorkflow(name, message string) (agent.Agent, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "release_human_approval_workflow"
	}
	message = strings.TrimSpace(message)
	if message == "" {
		message = "Review the release task evidence and reply with approval, rejection, or requested changes."
	}
	rerun := true
	approvalNode := workflow.NewEmittingFunctionNode[any, string]("request_human_approval",
		func(ctx agent.Context, input any, emit func(*session.Event) error) (string, error) {
			reply, err := workflow.ResumeOrRequestInput(ctx, emit, session.RequestInput{
				InterruptID: "release-human-approval-" + ctx.InvocationID(),
				Message:     message,
				Payload:     input,
			})
			if err != nil {
				return "", err
			}
			return fmt.Sprint(reply), nil
		},
		workflow.NodeConfig{RerunOnResume: &rerun},
	)
	resultNode := workflow.NewFunctionNode("record_human_approval",
		func(_ agent.Context, response string) (HumanApprovalResult, error) {
			response = strings.TrimSpace(response)
			if response == "" {
				return HumanApprovalResult{}, errors.New("human approval response is required")
			}
			return HumanApprovalResult{Status: "human_response_recorded", Response: response}, nil
		},
		workflow.NodeConfig{},
	)
	return workflowagent.New(workflowagent.Config{
		Name:        name,
		Description: "Graph HITL workflow that pauses release task execution for explicit human approval.",
		Edges:       workflow.Chain(workflow.Start, approvalNode, resultNode),
	})
}
