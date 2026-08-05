# The Ship Crew — ADK/A2A Primitives

## Overview

The Sovereignite software team is defined in `internal/shipcrew/` using ADK and
A2A framework primitives directly. No custom runtime, scheduler, lane runner,
static workflow platform, delegate CLI, bespoke permission layer, or
Nix-coupled harness is introduced.

We ship.

## The Crew

| Agent | Role | Mode | What they do |
|---|---|---|---|
| **`skipper`** | Coordinator | root | Runs the ship, delegates, keeps everyone on course |
| **`scout`** | Intake | `task` | Reads the issue, figures out what needs doing, can ask questions |
| **`builder`** | Implementation | `single_turn` | Does the work. Writes the code. Ships it. |
| **`prover`** | Validation | `single_turn` | Proves it works. Tests, lint, typecheck. No hand-waving. |
| **`critic`** | Review | `single_turn` | Catches what the builder missed. Honest feedback. |
| **`herald`** | Status/Handoff | `single_turn` | Reports the outcome. Posts the summary. Everyone knows. |
| **`retro`** | Self-improvement | `single_turn` | Runs the retrospective. Finds what broke. Proposes fixes with receipts. |

## ADK Primitives Used

### Collaboration Modes

- `task` mode on `scout` — may ask the user clarifying questions, auto-returns
  to skipper when done.
- `single_turn` on everyone else — executes one turn, returns automatically,
  can run in parallel.

### Delegation

When the skipper declares `SubAgents`, ADK automatically generates a delegation
tool for each crew member, named after the member. The skipper uses these tools
to route work — no custom lane runner or scheduler needed.

### Function Tools

Each crew member gets role-specific tools created with `functiontool.New`:

- **Scout:** `read_github_issue`, `extract_acceptance_criteria`
- **Builder:** `read_file`, `write_file` (confirmation required)
- **Prover:** `run_validation`
- **Critic:** `review_changes`
- **Herald:** `summarize_outcome`, `comment_on_task` (confirmation required)
- **Retro:** `analyze_run_outcomes`, `propose_improvement` (confirmation required)

Tools are ADK function tools, MCP toolsets, or direct API integrations. Crew
members do not call shell commands or orchestrate external executables.

### Tool Confirmation (Human Approval Gates)

Tools that mutate state or post comments use `RequireConfirmation: true`:

- `write_file` — builder needs human sign-off before writing
- `comment_on_task` — herald needs human sign-off before posting
- `propose_improvement` — retro needs human sign-off before filing

This is ADK's tool confirmation mechanism, not a custom approval layer.

### A2A Remote Crew Members

Optional remote agents for implementation, validation, or specialist work are
exposed and consumed through A2A using `remoteagent.NewA2A`. Container
lifecycle, workspace allocation, image builds, and mounts remain host
infrastructure concerns outside the crew.

## Responsibilities Outside the Crew

These are host infrastructure concerns, not crew responsibilities:

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

1. After a run completes, **retro** analyzes the outcome using
   `analyze_run_outcomes`.
2. If defects are found in prompts, tools, workflows, or evaluations, retro
   creates an `ImprovementProposal` with evidence.
3. The `propose_improvement` tool requires human confirmation before filing.
4. Filed proposals go through the normal issue → branch → PR → validation →
   human review flow.

Crew members cannot silently rewrite their own instructions, tools,
permissions, workflow definitions, or evaluation criteria. Self-improvement
proposals cannot escalate privileges, bypass branch protection, or bypass human
approval.

## Usage

```go
import (
    "github.com/sovereignite/sovereignite/internal/shipcrew"
    "google.golang.org/genai"
)

skipper, err := shipcrew.NewCrew(ctx, shipcrew.CrewConfig{
    ModelName:          "gemini-2.0-flash",
    GeminiClientConfig: &genai.ClientConfig{APIKey: "..."},
    RemoteCrewMembers: []shipcrew.RemoteCrewMember{
        {
            Name:            "remote_prover",
            Description:     "Remote validation worker",
            AgentCardSource: "http://localhost:9001",
        },
    },
})
```

## Running Tests

```bash
# Short mode (no API key required)
go test ./internal/shipcrew/... -short -v

# Full tests (requires GOOGLE_API_KEY)
go test ./internal/shipcrew/... -v
```

Full crew creation tests require a valid `GOOGLE_API_KEY` environment variable
for the Gemini model backend. Without the key, `gemini.NewModel` returns:
"api key is required for Google AI backend".
