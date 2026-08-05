# Release Agent Team — ADK/A2A Primitives

## Overview

The Sovereignite release task agent team is defined in `internal/releaseagent/`
using ADK and A2A framework primitives directly. No custom runtime, scheduler,
lane runner, static workflow platform, delegate CLI, bespoke permission layer,
or Nix-coupled harness is introduced.

## ADK Primitives Used

### LlmAgent with Collaboration Modes

Each agent is an `llmagent.LlmAgent` with a collaboration mode:

| Agent | Mode | Behavior |
|---|---|---|
| `release_coordinator` | (none, root) | Receives task requests, delegates to subagents |
| `issue_intake_agent` | `task` | May ask clarifying questions, auto-returns to coordinator |
| `implementation_agent` | `single_turn` | Executes one turn, returns automatically |
| `validation_agent` | `single_turn` | Executes one turn, returns automatically |
| `review_agent` | `single_turn` | Executes one turn, returns automatically |
| `status_handoff_agent` | `single_turn` | Executes one turn, returns automatically |
| `improvement_reviewer_agent` | `single_turn` | Executes one turn, returns automatically |

The `task` mode on `issue_intake_agent` allows it to ask the user clarifying
questions before returning. The `single_turn` mode on other agents enables
parallel execution and automatic return to the coordinator.

### Delegation

When the coordinator declares `SubAgents`, ADK automatically generates a
delegation tool for each subagent, named after the subagent itself. The
coordinator uses these tools to route work — no custom lane runner or scheduler
is needed.

### Function Tools

Each agent receives role-specific tools created with `functiontool.New`:

- **Intake tools:** `read_github_issue`, `extract_acceptance_criteria`
- **Implementation tools:** `read_file`, `write_file` (confirmation required)
- **Validation tools:** `run_validation`
- **Review tools:** `review_changes`
- **Status tools:** `summarize_outcome`, `comment_on_task` (confirmation required)
- **Improvement tools:** `analyze_run_outcomes`, `propose_improvement` (confirmation required)

Tools are ADK function tools, MCP toolsets, or direct API integrations. Agents
do not call shell commands or orchestrate external executables.

### Tool Confirmation (Human Approval Gates)

Tools that mutate state or post comments use `RequireConfirmation: true`:

- `write_file` — requires human confirmation before writing
- `comment_on_task` — requires human confirmation before posting
- `propose_improvement` — requires human confirmation before filing

This implements human-in-the-loop gates through ADK's tool confirmation
mechanism, not through a custom approval layer.

### A2A Remote Workers

Optional remote agents for implementation, validation, or specialist work are
exposed and consumed through A2A using `remoteagent.NewA2A`. Each remote worker
is described by a name, description, and agent card source URL. Container
lifecycle, workspace allocation, image builds, and mounts remain host
infrastructure concerns outside the agent team.

## Responsibilities Outside the Agent Team

The following are host infrastructure concerns, not agent responsibilities:

- Container lifecycle (create, start, stop, destroy)
- Worktree allocation and cleanup
- Image builds and registry pushes
- Volume mounts and filesystem isolation
- Network configuration for A2A endpoints
- Secret management (API keys, credentials)
- GitHub API authentication
- Branch protection configuration
- CI/CD pipeline execution

## Recursive Self-Improvement

Self-improvement is modeled as explicit, auditable follow-up task proposals:

1. After a release task run completes, the `improvement_reviewer_agent` analyzes
   the run outcome using `analyze_run_outcomes`.
2. If defects are found in prompts, tools, workflows, or evaluations, the agent
   creates an `ImprovementProposal` with:
   - `RunID` — the run that triggered the proposal
   - `Category` — one of: prompt, tool, workflow, evaluation
   - `Defect` — the identified defect or gap
   - `Evidence` — evidence from the run
   - `Proposal` — the narrow recommended change
   - `IssueTitle` — suggested GitHub issue title
3. The `propose_improvement` tool requires human confirmation before filing.
4. Filed proposals go through the normal issue → branch → PR → validation →
   human review flow.

Agents cannot silently rewrite their own instructions, tools, permissions,
workflow definitions, or evaluation criteria. Self-improvement proposals cannot
escalate privileges, bypass branch protection, or bypass human approval.

## Usage

```go
import (
    "github.com/sovereignite/sovereignite/internal/releaseagent"
    "google.golang.org/genai"
)

team, err := releaseagent.NewTeam(ctx, releaseagent.Config{
    ModelName:          "gemini-2.0-flash",
    GeminiClientConfig: &genai.ClientConfig{APIKey: "..."},
    A2ARemoteWorkers: []releaseagent.A2ARemoteWorker{
        {
            Name:            "remote_validator",
            Description:     "Remote validation worker",
            AgentCardSource: "http://localhost:9001",
        },
    },
})
```

## Running Tests

```bash
# Short mode (no API key required)
go test ./internal/releaseagent/... -short -v

# Full tests (requires GOOGLE_API_KEY)
go test ./internal/releaseagent/... -v
```

Full team creation tests require a valid `GOOGLE_API_KEY` environment variable
for the Gemini model backend. Without the key, `gemini.NewModel` returns:
"api key is required for Google AI backend".
