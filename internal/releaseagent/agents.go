// Package releaseagent defines the Sovereignite release task agent team using
// ADK and A2A framework primitives directly.
//
// The team is composed of a root coordinator and role-specific subagents.
// Each agent is an ADK LlmAgent with a collaboration mode, role-specific
// tools, and explicit delegation through the coordinator.
//
// Agents do not receive merge or bypass authority. Agents do not call shell
// commands or orchestrate external executables. Container lifecycle, worktree
// allocation, image builds, and mounts are host infrastructure concerns
// outside the agent team.
//
// Recursive self-improvement is modeled as explicit, auditable follow-up task
// proposals with evidence from the run that triggered them.
package releaseagent

import (
	"context"
	"fmt"

	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/agent/llmagent"
	"google.golang.org/adk/v2/agent/remoteagent"
	"google.golang.org/adk/v2/model/gemini"
	"google.golang.org/adk/v2/tool"
	"google.golang.org/adk/v2/tool/functiontool"
	"google.golang.org/genai"
)

// Agent names used for delegation and identification.
const (
	CoordinatorName       = "release_coordinator"
	IntakeAgentName       = "issue_intake_agent"
	ImplementationName    = "implementation_agent"
	ValidationName        = "validation_agent"
	ReviewName            = "review_agent"
	StatusHandoffName     = "status_handoff_agent"
	ImprovementReviewerName = "improvement_reviewer_agent"
)

// ImprovementProposal represents a structured, auditable self-improvement
// proposal with evidence from the run that triggered it. Proposals go through
// the normal issue, branch, PR, validation, and human review flow.
type ImprovementProposal struct {
	RunID       string `json:"run_id"       jsonschema:"The run that triggered this proposal."`
	Category    string `json:"category"     jsonschema:"One of: prompt, tool, workflow, evaluation."`
	Defect      string `json:"defect"       jsonschema:"The identified defect or gap."`
	Evidence    string `json:"evidence"     jsonschema:"Evidence from the run supporting this proposal."`
	Proposal    string `json:"proposal"     jsonschema:"The narrow recommended change."`
	IssueTitle  string `json:"issue_title"  jsonschema:"Suggested GitHub issue title for this proposal."`
}

// RunOutcomeSummary holds the outcome of a completed release task run for
// analysis by the improvement reviewer.
type RunOutcomeSummary struct {
	RunID            string   `json:"run_id"`
	TaskIssueNumber  int      `json:"task_issue_number"`
	Outcome          string   `json:"outcome"` // success, partial, failed
	ValidationPassed bool     `json:"validation_passed"`
	ReviewPassed     bool     `json:"review_passed"`
	DurationMinutes  int      `json:"duration_minutes"`
	Errors           []string `json:"errors,omitempty"`
	Notes            []string `json:"notes,omitempty"`
}

// IssueData holds extracted issue information from the intake agent.
type IssueData struct {
	Number            int      `json:"number"`
	Title             string   `json:"title"`
	Constraints       []string `json:"constraints"`
	AcceptanceCriteria []string `json:"acceptance_criteria"`
	OpenQuestions      []string `json:"open_questions"`
	ExpectedOutputs    []string `json:"expected_outputs"`
}

// ValidationResult holds the output of a validation run.
type ValidationResult struct {
	Passed   bool     `json:"passed"`
	Checks   []Check  `json:"checks"`
	Summary  string   `json:"summary"`
}

// Check is a single validation check result.
type Check struct {
	Name    string `json:"name"`
	Status  string `json:"status"` // pass, fail, skip
	Details string `json:"details,omitempty"`
}

// ReviewResult holds the output of a review pass.
type ReviewResult struct {
	Approved       bool     `json:"approved"`
	Risks          []string `json:"risks"`
	MissingTests   []string `json:"missing_tests"`
	PolicyViolations []string `json:"policy_violations"`
	Summary        string   `json:"summary"`
}

// StatusReport holds the handoff summary.
type StatusReport struct {
	IssueNumber    int    `json:"issue_number"`
	Outcome        string `json:"outcome"`
	ValidationPass bool   `json:"validation_pass"`
	ReviewPass     bool   `json:"review_pass"`
	ResidualRisks  []string `json:"residual_risks,omitempty"`
	Summary        string `json:"summary"`
}

// --- Tool definitions ---

func newIntakeTools() ([]tool.Tool, error) {
	readIssue, err := functiontool.New(functiontool.Config{
		Name:        "read_github_issue",
		Description: "Reads a GitHub issue by number and returns its title, body, labels, and comments.",
	}, func(_ agent.Context, args struct {
		IssueNumber int `json:"issue_number" jsonschema:"The GitHub issue number to read."`
	}) (IssueData, error) {
		// In production this calls the GitHub API via MCP toolset or direct
		// integration. The agent team does not shell out to gh or curl.
		return IssueData{
			Number: args.IssueNumber,
			Title:  "(issue title from GitHub API)",
		}, nil
	})
	if err != nil {
		return nil, fmt.Errorf("read_github_issue: %w", err)
	}

	extractCriteria, err := functiontool.New(functiontool.Config{
		Name:        "extract_acceptance_criteria",
		Description: "Extracts constraints, acceptance criteria, open questions, and expected outputs from issue text.",
	}, func(_ agent.Context, args struct {
		IssueBody string `json:"issue_body" jsonschema:"The full issue body text."`
	}) (IssueData, error) {
		return IssueData{}, nil
	})
	if err != nil {
		return nil, fmt.Errorf("extract_acceptance_criteria: %w", err)
	}

	return []tool.Tool{readIssue, extractCriteria}, nil
}

func newImplementationTools() ([]tool.Tool, error) {
	readFile, err := functiontool.New(functiontool.Config{
		Name:        "read_file",
		Description: "Reads the contents of a file at the given path within the repository.",
	}, func(_ agent.Context, args struct {
		Path string `json:"path" jsonschema:"Repository-relative file path to read."`
	}) (string, error) {
		return "", nil
	})
	if err != nil {
		return nil, fmt.Errorf("read_file: %w", err)
	}

	writeFile, err := functiontool.New(functiontool.Config{
		Name:                "write_file",
		Description:         "Writes content to a file at the given path. Requires human confirmation.",
		RequireConfirmation: true,
	}, func(_ agent.Context, args struct {
		Path    string `json:"path"    jsonschema:"Repository-relative file path to write."`
		Content string `json:"content" jsonschema:"The content to write."`
	}) (string, error) {
		return "written", nil
	})
	if err != nil {
		return nil, fmt.Errorf("write_file: %w", err)
	}

	return []tool.Tool{readFile, writeFile}, nil
}

func newValidationTools() ([]tool.Tool, error) {
	runValidation, err := functiontool.New(functiontool.Config{
		Name:        "run_validation",
		Description: "Runs validation checks (lint, typecheck, targeted tests) and returns structured results.",
	}, func(_ agent.Context, args struct {
		CheckType string `json:"check_type" jsonschema:"Type of validation: lint, typecheck, test, all."`
	}) (ValidationResult, error) {
		return ValidationResult{}, nil
	})
	if err != nil {
		return nil, fmt.Errorf("run_validation: %w", err)
	}

	return []tool.Tool{runValidation}, nil
}

func newReviewTools() ([]tool.Tool, error) {
	reviewChanges, err := functiontool.New(functiontool.Config{
		Name:        "review_changes",
		Description: "Reviews staged or committed changes against the issue requirements.",
	}, func(_ agent.Context, args struct {
		IssueNumber int    `json:"issue_number" jsonschema:"The issue number to review against."`
		DiffSummary string `json:"diff_summary" jsonschema:"Summary of changes to review."`
	}) (ReviewResult, error) {
		return ReviewResult{}, nil
	})
	if err != nil {
		return nil, fmt.Errorf("review_changes: %w", err)
	}

	return []tool.Tool{reviewChanges}, nil
}

func newStatusHandoffTools() ([]tool.Tool, error) {
	summarizeOutcome, err := functiontool.New(functiontool.Config{
		Name:        "summarize_outcome",
		Description: "Summarizes the outcome of a release task run including validation and review results.",
	}, func(_ agent.Context, args StatusReport) (string, error) {
		return "", nil
	})
	if err != nil {
		return nil, fmt.Errorf("summarize_outcome: %w", err)
	}

	commentOnTask, err := functiontool.New(functiontool.Config{
		Name:                "comment_on_task",
		Description:         "Posts a summary comment on a GitHub issue or PR. Requires human confirmation.",
		RequireConfirmation: true,
	}, func(_ agent.Context, args struct {
		TargetType  string `json:"target_type"  jsonschema:"issue or pr."`
		TargetNumber int   `json:"target_number" jsonschema:"The issue or PR number."`
		Body        string `json:"body"          jsonschema:"The comment body."`
	}) (string, error) {
		return "commented", nil
	})
	if err != nil {
		return nil, fmt.Errorf("comment_on_task: %w", err)
	}

	return []tool.Tool{summarizeOutcome, commentOnTask}, nil
}

func newImprovementTools() ([]tool.Tool, error) {
	analyzeOutcomes, err := functiontool.New(functiontool.Config{
		Name:        "analyze_run_outcomes",
		Description: "Analyzes completed run outcomes to identify defects in prompts, tools, workflows, or evaluations.",
	}, func(_ agent.Context, args struct {
		Outcome RunOutcomeSummary `json:"outcome" jsonschema:"The completed run outcome to analyze."`
	}) ([]ImprovementProposal, error) {
		return nil, nil
	})
	if err != nil {
		return nil, fmt.Errorf("analyze_run_outcomes: %w", err)
	}

	proposeImprovement, err := functiontool.New(functiontool.Config{
		Name:                "propose_improvement",
		Description:         "Creates an auditable improvement proposal with evidence. Requires human confirmation before filing.",
		RequireConfirmation: true,
	}, func(_ agent.Context, args ImprovementProposal) (string, error) {
		return "proposal_created", nil
	})
	if err != nil {
		return nil, fmt.Errorf("propose_improvement: %w", err)
	}

	return []tool.Tool{analyzeOutcomes, proposeImprovement}, nil
}

// --- Agent constructors ---

// Config holds configuration for building the release agent team.
type Config struct {
	// ModelName is the ADK model identifier (e.g. "gemini-2.0-flash").
	ModelName string

	// GeminiClientConfig is the genai client configuration for the model.
	GeminiClientConfig *genai.ClientConfig

	// A2ARemoteWorkers lists optional remote agent endpoints for
	// implementation, validation, or specialist workers exposed over A2A.
	// Each entry is a base URL serving an A2A agent card at
	// /.well-known/agent-card.json.
	A2ARemoteWorkers []A2ARemoteWorker
}

// A2ARemoteWorker describes a remote agent available over A2A.
type A2ARemoteWorker struct {
	Name            string
	Description     string
	AgentCardSource string
}

// NewTeam builds the full release agent team and returns the root coordinator.
// The team uses ADK collaboration modes, delegation, tool confirmation for
// human approval gates, and optional A2A remote workers.
func NewTeam(ctx context.Context, cfg Config) (agent.Agent, error) {
	model, err := gemini.NewModel(ctx, cfg.ModelName, cfg.GeminiClientConfig)
	if err != nil {
		return nil, fmt.Errorf("releaseagent: failed to create model: %w", err)
	}

	// Build role-specific tools.
	intakeTools, err := newIntakeTools()
	if err != nil {
		return nil, err
	}
	implTools, err := newImplementationTools()
	if err != nil {
		return nil, err
	}
	validationTools, err := newValidationTools()
	if err != nil {
		return nil, err
	}
	reviewTools, err := newReviewTools()
	if err != nil {
		return nil, err
	}
	statusTools, err := newStatusHandoffTools()
	if err != nil {
		return nil, err
	}
	improvementTools, err := newImprovementTools()
	if err != nil {
		return nil, err
	}

	// Issue intake agent: task mode — may ask clarifying questions,
	// automatically returns to coordinator when done.
	intakeAgent, err := llmagent.New(llmagent.Config{
		Name:        IntakeAgentName,
		Model:       model,
		Mode:        llmagent.ModeTask,
		Description: "Reads assigned GitHub issues and extracts constraints, acceptance criteria, open questions, and expected outputs.",
		Instruction: `You are the issue intake agent. Your job is to:
1. Read the assigned GitHub issue using read_github_issue.
2. Extract constraints, acceptance criteria, open questions, and expected outputs using extract_acceptance_criteria.
3. Return a structured IssueData summary to the coordinator.
Do not modify any files. Do not run any commands.`,
		Tools: intakeTools,
	})
	if err != nil {
		return nil, fmt.Errorf("releaseagent: intake agent: %w", err)
	}

	// Implementation agent: single_turn mode — executes one turn and
	// returns automatically. Can run in parallel with peer agents.
	implementationAgent, err := llmagent.New(llmagent.Config{
		Name:        ImplementationName,
		Model:       model,
		Mode:        llmagent.ModeSingleTurn,
		Description: "Performs scoped implementation work using only exposed ADK tools, MCP toolsets, or direct API capabilities.",
		Instruction: `You are the implementation agent. Your job is to:
1. Read the issue requirements passed by the coordinator.
2. Read relevant files using read_file.
3. Make scoped changes using write_file (requires human confirmation).
4. Return a summary of changes made.
You must not call shell commands or orchestrate external executables.
You must not merge pull requests or bypass branch protection.`,
		Tools: implTools,
	})
	if err != nil {
		return nil, fmt.Errorf("releaseagent: implementation agent: %w", err)
	}

	// Validation agent: single_turn mode.
	validationAgent, err := llmagent.New(llmagent.Config{
		Name:        ValidationName,
		Model:       model,
		Mode:        llmagent.ModeSingleTurn,
		Description: "Validates work through approved ADK tools, MCP toolsets, or direct API integrations and reports results.",
		Instruction: `You are the validation agent. Your job is to:
1. Run validation checks using run_validation (lint, typecheck, tests).
2. Return a structured ValidationResult with pass/fail status for each check.
You must not call shell commands or orchestrate external executables.
Validation runs through approved ADK tools and API integrations only.`,
		Tools: validationTools,
	})
	if err != nil {
		return nil, fmt.Errorf("releaseagent: validation agent: %w", err)
	}

	// Review agent: single_turn mode.
	reviewAgent, err := llmagent.New(llmagent.Config{
		Name:        ReviewName,
		Model:       model,
		Mode:        llmagent.ModeSingleTurn,
		Description: "Reviews changes against the issue, regressions, missing tests, risks, and policy boundaries.",
		Instruction: `You are the review agent. Your job is to:
1. Review the changes against the issue requirements using review_changes.
2. Check for regressions, missing tests, risks, and policy violations.
3. Return a structured ReviewResult.
You must not approve or merge pull requests. Final approval and merge remain human-controlled.`,
		Tools: reviewTools,
	})
	if err != nil {
		return nil, fmt.Errorf("releaseagent: review agent: %w", err)
	}

	// Status handoff agent: single_turn mode.
	statusAgent, err := llmagent.New(llmagent.Config{
		Name:        StatusHandoffName,
		Model:       model,
		Mode:        llmagent.ModeSingleTurn,
		Description: "Summarizes outcomes, validation, residual risks, and comments on tasks or PRs when appropriate.",
		Instruction: `You are the status handoff agent. Your job is to:
1. Summarize the run outcome using summarize_outcome.
2. Post a summary comment on the GitHub issue or PR using comment_on_task (requires human confirmation).
3. Return the StatusReport to the coordinator.
Do not merge or approve PRs.`,
		Tools: statusTools,
	})
	if err != nil {
		return nil, fmt.Errorf("releaseagent: status handoff agent: %w", err)
	}

	// Improvement reviewer agent: single_turn mode. Reviews completed runs
	// and proposes evidence-backed follow-up tasks.
	improvementAgent, err := llmagent.New(llmagent.Config{
		Name:        ImprovementReviewerName,
		Model:       model,
		Mode:        llmagent.ModeSingleTurn,
		Description: "Reviews completed runs, identifies defects in prompts/tools/workflows/evaluations, and proposes evidence-backed follow-up tasks.",
		Instruction: `You are the improvement reviewer agent. Your job is to:
1. Analyze the completed run outcome using analyze_run_outcomes.
2. Identify defects in prompts, tools, workflows, or evaluations.
3. Create an ImprovementProposal with evidence using propose_improvement (requires human confirmation).
Improvement proposals must:
- Include evidence from the run that triggered them.
- Propose a narrow, specific change.
- Be filed as normal tracked tasks through the issue/branch/PR flow.
You must not silently modify agent instructions, tools, permissions, or workflow definitions.`,
		Tools: improvementTools,
	})
	if err != nil {
		return nil, fmt.Errorf("releaseagent: improvement agent: %w", err)
	}

	// Collect subagents. Remote A2A workers are added as subagents when
	// configured, enabling distribution or isolation for implementation,
	// validation, or specialist work.
	subAgents := []agent.Agent{
		intakeAgent,
		implementationAgent,
		validationAgent,
		reviewAgent,
		statusAgent,
		improvementAgent,
	}

	for _, rw := range cfg.A2ARemoteWorkers {
		remote, err := remoteagent.NewA2A(remoteagent.A2AConfig{
			Name:            rw.Name,
			Description:     rw.Description,
			AgentCardSource: rw.AgentCardSource,
		})
		if err != nil {
			return nil, fmt.Errorf("releaseagent: remote worker %q: %w", rw.Name, err)
		}
		subAgents = append(subAgents, remote)
	}

	// Root coordinator agent: receives task requests, delegates to role
	// agents, tracks handoffs, and keeps human-controlled gates explicit.
	// ADK auto-generates delegation tools named after each subagent.
	coordinator, err := llmagent.New(llmagent.Config{
		Name:  CoordinatorName,
		Model: model,
		Description: `Root coordinator for Sovereignite release task work.
Receives task requests, delegates to role-specific agents, tracks handoffs,
and keeps human-controlled gates explicit.`,
		Instruction: `You are the release coordinator for Sovereignite. Your job is to:
1. Receive a task request (GitHub issue number).
2. Delegate to issue_intake_agent to read and extract requirements.
3. Delegate to implementation_agent to perform scoped changes.
4. Delegate to validation_agent to validate the work.
5. Delegate to review_agent to review changes.
6. Delegate to status_handoff_agent to summarize and comment.
7. Delegate to improvement_reviewer_agent to analyze the run and propose improvements.

Rules:
- Use delegation tools to route work to subagents. Do not hardcode lanes.
- Human approval gates are enforced through tool confirmation on write_file and comment_on_task.
- You must not merge pull requests or bypass branch protection.
- You must not call shell commands or orchestrate external executables.
- Parallel work is represented through ADK single_turn subagents.
- Recursive self-improvement proposals go through the normal issue/branch/PR flow.`,
		SubAgents: subAgents,
	})
	if err != nil {
		return nil, fmt.Errorf("releaseagent: coordinator: %w", err)
	}

	return coordinator, nil
}
