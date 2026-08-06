// Package shipcrew defines the Sovereignite software team using ADK and A2A
// framework primitives directly.
//
// The crew is composed of a skipper and role-specific crew members. Each agent
// is an ADK LlmAgent with a collaboration mode, role-specific tools, and
// explicit delegation through the skipper.
//
// Agents do not receive merge or bypass authority. Agents do not call shell
// commands or orchestrate external executables. Container lifecycle, worktree
// allocation, image builds, and mounts are host infrastructure concerns
// outside the crew.
//
// Recursive self-improvement is modeled as explicit, auditable follow-up task
// proposals with evidence from the run that triggered them.
package shipcrew

import (
	"context"
	"fmt"

	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/agent/llmagent"
	"google.golang.org/adk/v2/agent/remoteagent/v2"
	"google.golang.org/adk/v2/model"
	"google.golang.org/adk/v2/tool"
	"google.golang.org/adk/v2/tool/functiontool"
)

// Agent names used for delegation and identification.
const (
	SkipperName   = "skipper"
	ScoutName     = "scout"
	BuilderName   = "builder"
	ProverName    = "prover"
	CriticName    = "critic"
	HeraldName    = "herald"
	RetroName     = "retro"
)

// ImprovementProposal represents a structured, auditable self-improvement
// proposal with evidence from the run that triggered it. Proposals go through
// the normal issue, branch, PR, validation, and human review flow.
type ImprovementProposal struct {
	RunID      string `json:"run_id"      jsonschema:"The run that triggered this proposal."`
	Category   string `json:"category"    jsonschema:"One of: prompt, tool, workflow, evaluation."`
	Defect     string `json:"defect"      jsonschema:"The identified defect or gap."`
	Evidence   string `json:"evidence"    jsonschema:"Evidence from the run supporting this proposal."`
	Proposal   string `json:"proposal"    jsonschema:"The narrow recommended change."`
	IssueTitle string `json:"issue_title" jsonschema:"Suggested GitHub issue title for this proposal."`
}

// RunOutcomeSummary holds the outcome of a completed run for analysis by retro.
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

// IssueData holds extracted issue information from the scout.
type IssueData struct {
	Number             int      `json:"number"`
	Title              string   `json:"title"`
	Constraints        []string `json:"constraints"`
	AcceptanceCriteria []string `json:"acceptance_criteria"`
	OpenQuestions      []string `json:"open_questions"`
	ExpectedOutputs    []string `json:"expected_outputs"`
}

// ValidationResult holds the output of a validation run from the prover.
type ValidationResult struct {
	Passed  bool   `json:"passed"`
	Checks  []Check `json:"checks"`
	Summary string  `json:"summary"`
}

// Check is a single validation check result.
type Check struct {
	Name    string `json:"name"`
	Status  string `json:"status"` // pass, fail, skip
	Details string `json:"details,omitempty"`
}

// ReviewResult holds the output of a review pass from the critic.
type ReviewResult struct {
	Approved         bool     `json:"approved"`
	Risks            []string `json:"risks"`
	MissingTests     []string `json:"missing_tests"`
	PolicyViolations []string `json:"policy_violations"`
	Summary          string   `json:"summary"`
}

// StatusReport holds the handoff summary from the herald.
type StatusReport struct {
	IssueNumber    int      `json:"issue_number"`
	Outcome        string   `json:"outcome"`
	ValidationPass bool     `json:"validation_pass"`
	ReviewPass     bool     `json:"review_pass"`
	ResidualRisks  []string `json:"residual_risks,omitempty"`
	Summary        string   `json:"summary"`
}

// --- Tool definitions ---

func newScoutTools() ([]tool.Tool, error) {
	readIssue, err := functiontool.New(functiontool.Config{
		Name:        "read_github_issue",
		Description: "Reads a GitHub issue by number and returns its title, body, labels, and comments.",
	}, func(_ agent.Context, args struct {
		IssueNumber int `json:"issue_number" jsonschema:"The GitHub issue number to read."`
	}) (IssueData, error) {
		// In production this calls the GitHub API via MCP toolset or direct
		// integration. The crew does not shell out to gh or curl.
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

func newBuilderTools() ([]tool.Tool, error) {
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

func newProverTools() ([]tool.Tool, error) {
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

func newCriticTools() ([]tool.Tool, error) {
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

func newHeraldTools() ([]tool.Tool, error) {
	summarizeOutcome, err := functiontool.New(functiontool.Config{
		Name:        "summarize_outcome",
		Description: "Summarizes the outcome of a run including validation and review results.",
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
		TargetType   string `json:"target_type"   jsonschema:"issue or pr."`
		TargetNumber int    `json:"target_number" jsonschema:"The issue or PR number."`
		Body         string `json:"body"          jsonschema:"The comment body."`
	}) (string, error) {
		return "commented", nil
	})
	if err != nil {
		return nil, fmt.Errorf("comment_on_task: %w", err)
	}

	return []tool.Tool{summarizeOutcome, commentOnTask}, nil
}

func newRetroTools() ([]tool.Tool, error) {
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

// --- Crew construction ---

// CrewConfig holds configuration for building the crew.
type CrewConfig struct {
	// Model is the LLM used by all crew members. Accepts any model.LLM
	// implementation: gemini.NewModel, openaimodel.NewModel, or a custom one.
	Model model.LLM

	// RemoteCrewMembers lists optional remote agent endpoints for
	// implementation, validation, or specialist work exposed over A2A.
	// Each entry is a base URL serving an A2A agent card at
	// /.well-known/agent-card.json.
	RemoteCrewMembers []RemoteCrewMember
}

// RemoteCrewMember describes a remote agent available over A2A.
type RemoteCrewMember struct {
	Name            string
	Description     string
	AgentCardSource string
}

// NewCrew builds the full crew and returns the skipper. The crew uses ADK
// collaboration modes, delegation, tool confirmation for human approval gates,
// and optional A2A remote crew members.
func NewCrew(ctx context.Context, cfg CrewConfig) (agent.Agent, error) {
	if cfg.Model == nil {
		return nil, fmt.Errorf("shipcrew: Model is required")
	}

	llm := cfg.Model

	// Build role-specific tools.
	scoutTools, err := newScoutTools()
	if err != nil {
		return nil, err
	}
	builderTools, err := newBuilderTools()
	if err != nil {
		return nil, err
	}
	proverTools, err := newProverTools()
	if err != nil {
		return nil, err
	}
	criticTools, err := newCriticTools()
	if err != nil {
		return nil, err
	}
	heraldTools, err := newHeraldTools()
	if err != nil {
		return nil, err
	}
	retroTools, err := newRetroTools()
	if err != nil {
		return nil, err
	}

	// Scout: task mode — may ask clarifying questions,
	// automatically returns to skipper when done.
	scout, err := llmagent.New(llmagent.Config{
		Name:        ScoutName,
		Model:       llm,
		Mode:        llmagent.ModeTask,
		Description: "Reads assigned GitHub issues and extracts constraints, acceptance criteria, open questions, and expected outputs.",
		Instruction: `You are the scout. Your job is to:
1. Read the assigned GitHub issue using read_github_issue.
2. Extract constraints, acceptance criteria, open questions, and expected outputs using extract_acceptance_criteria.
3. Return a structured IssueData summary to the skipper.
Do not modify any files. Do not run any commands.`,
		Tools: scoutTools,
	})
	if err != nil {
		return nil, fmt.Errorf("shipcrew: scout: %w", err)
	}

	// Builder: single_turn mode — executes one turn and
	// returns automatically. Can run in parallel with peer agents.
	builder, err := llmagent.New(llmagent.Config{
		Name:        BuilderName,
		Model:       llm,
		Mode:        llmagent.ModeSingleTurn,
		Description: "Performs scoped implementation work using only exposed ADK tools, MCP toolsets, or direct API capabilities.",
		Instruction: `You are the builder. Your job is to:
1. Read the issue requirements passed by the skipper.
2. Read relevant files using read_file.
3. Make scoped changes using write_file (requires human confirmation).
4. Return a summary of changes made.
You must not call shell commands or orchestrate external executables.
You must not merge pull requests or bypass branch protection.`,
		Tools: builderTools,
	})
	if err != nil {
		return nil, fmt.Errorf("shipcrew: builder: %w", err)
	}

	// Prover: single_turn mode.
	prover, err := llmagent.New(llmagent.Config{
		Name:        ProverName,
		Model:       llm,
		Mode:        llmagent.ModeSingleTurn,
		Description: "Validates work through approved ADK tools, MCP toolsets, or direct API integrations and reports results.",
		Instruction: `You are the prover. Your job is to:
1. Run validation checks using run_validation (lint, typecheck, tests).
2. Return a structured ValidationResult with pass/fail status for each check.
You must not call shell commands or orchestrate external executables.
Validation runs through approved ADK tools and API integrations only.`,
		Tools: proverTools,
	})
	if err != nil {
		return nil, fmt.Errorf("shipcrew: prover: %w", err)
	}

	// Critic: single_turn mode.
	critic, err := llmagent.New(llmagent.Config{
		Name:        CriticName,
		Model:       llm,
		Mode:        llmagent.ModeSingleTurn,
		Description: "Reviews changes against the issue, regressions, missing tests, risks, and policy boundaries.",
		Instruction: `You are the critic. Your job is to:
1. Review the changes against the issue requirements using review_changes.
2. Check for regressions, missing tests, risks, and policy violations.
3. Return a structured ReviewResult.
You must not approve or merge pull requests. Final approval and merge remain human-controlled.`,
		Tools: criticTools,
	})
	if err != nil {
		return nil, fmt.Errorf("shipcrew: critic: %w", err)
	}

	// Herald: single_turn mode.
	herald, err := llmagent.New(llmagent.Config{
		Name:        HeraldName,
		Model:       llm,
		Mode:        llmagent.ModeSingleTurn,
		Description: "Summarizes outcomes, validation, residual risks, and comments on tasks or PRs when appropriate.",
		Instruction: `You are the herald. Your job is to:
1. Summarize the run outcome using summarize_outcome.
2. Post a summary comment on the GitHub issue or PR using comment_on_task (requires human confirmation).
3. Return the StatusReport to the skipper.
Do not merge or approve PRs.`,
		Tools: heraldTools,
	})
	if err != nil {
		return nil, fmt.Errorf("shipcrew: herald: %w", err)
	}

	// Retro: single_turn mode. Reviews completed runs
	// and proposes evidence-backed follow-up tasks.
	retro, err := llmagent.New(llmagent.Config{
		Name:        RetroName,
		Model:       llm,
		Mode:        llmagent.ModeSingleTurn,
		Description: "Reviews completed runs, identifies defects in prompts/tools/workflows/evaluations, and proposes evidence-backed follow-up tasks.",
		Instruction: `You are the retro. Your job is to:
1. Analyze the completed run outcome using analyze_run_outcomes.
2. Identify defects in prompts, tools, workflows, or evaluations.
3. Create an ImprovementProposal with evidence using propose_improvement (requires human confirmation).
Improvement proposals must:
- Include evidence from the run that triggered them.
- Propose a narrow, specific change.
- Be filed as normal tracked tasks through the issue/branch/PR flow.
You must not silently modify agent instructions, tools, permissions, or workflow definitions.`,
		Tools: retroTools,
	})
	if err != nil {
		return nil, fmt.Errorf("shipcrew: retro: %w", err)
	}

	// Collect subagents. Remote A2A crew members are added as subagents
	// when configured, enabling distribution or isolation for
	// implementation, validation, or specialist work.
	subAgents := []agent.Agent{
		scout,
		builder,
		prover,
		critic,
		herald,
		retro,
	}

	for _, rw := range cfg.RemoteCrewMembers {
		remote, err := remoteagent.NewA2A(remoteagent.A2AConfig{
			Name:              rw.Name,
			Description:       rw.Description,
			AgentCardProvider: remoteagent.NewAgentCardProvider(rw.AgentCardSource),
		})
		if err != nil {
			return nil, fmt.Errorf("shipcrew: remote crew member %q: %w", rw.Name, err)
		}
		subAgents = append(subAgents, remote)
	}

	// Skipper: root agent that receives task requests, delegates to crew
	// members, tracks handoffs, and keeps human-controlled gates explicit.
	// ADK auto-generates delegation tools named after each subagent.
	skipper, err := llmagent.New(llmagent.Config{
		Name:  SkipperName,
		Model: llm,
		Description: `Skipper of the Sovereignite crew.
Receives task requests, delegates to crew members, tracks handoffs,
and keeps human-controlled gates explicit.`,
		Instruction: `You are the skipper. Your job is to:
1. Receive a task request (GitHub issue number).
2. Delegate to the scout to read and extract requirements.
3. Delegate to the builder to perform scoped changes.
4. Delegate to the prover to validate the work.
5. Delegate to the critic to review changes.
6. Delegate to the herald to summarize and comment.
7. Delegate to retro to analyze the run and propose improvements.

Rules:
- Use delegation tools to route work to crew members. Do not hardcode lanes.
- Human approval gates are enforced through tool confirmation on write_file and comment_on_task.
- You must not merge pull requests or bypass branch protection.
- You must not call shell commands or orchestrate external executables.
- Parallel work is represented through ADK single_turn subagents.
- Recursive self-improvement proposals go through the normal issue/branch/PR flow.`,
		SubAgents: subAgents,
	})
	if err != nil {
		return nil, fmt.Errorf("shipcrew: skipper: %w", err)
	}

	return skipper, nil
}
