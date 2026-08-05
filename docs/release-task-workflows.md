# Release Task Workflows

Sovereignite release task coordination is modeled as an ADK agent team in
`internal/releaseworkflow`. The implementation composes ADK/A2A primitives and
does not define a custom runtime, scheduler, lane runner, delegate CLI, or
Nix-coupled harness.

## ADK/A2A Primitives

The root coordinator is `release_coordinator`, an ADK `llmagent` with
role-specific subagents declared through `SubAgents`. ADK generates delegation
tools for those subagents.

The role agents are:

| Agent | ADK mode | Responsibility |
| --- | --- | --- |
| `issue_intake_agent` | `task` | Read assigned GitHub tasks and extract constraints, acceptance criteria, open questions, and expected outputs. |
| `implementation_agent` | `single_turn` | Perform scoped implementation through exposed ADK tools, MCP toolsets, A2A agents, in-process functions, or direct API integrations. |
| `validation_agent` | `single_turn` | Validate work through approved tools and report exact results or blockers. |
| `review_agent` | `single_turn` | Review changes for issue fit, regressions, missing tests, risks, and policy boundaries. |
| `status_handoff_agent` | `single_turn` | Summarize outcomes, validation, residual risks, and task or PR status. |
| `improvement_reviewer_agent` | `single_turn` | Propose evidence-backed follow-up tasks for workflow, tooling, prompt, or evaluation improvements. |

Role capabilities are assigned by ADK tool exposure. Callers provide ADK tools,
MCP toolsets, A2A agents, in-process functions, or direct API tools to the role
that needs them. The package does not translate those tools into a separate
permission system.

Remote or isolated workers are consumed with ADK A2A remote-agent support from
agent cards. A host can expose a selected ADK agent with the ADK A2A launcher and
then pass its agent-card URL as a `RemoteWorker`. Local subagents remain the
default for in-process coordination.

Human gates use ADK primitives:

- `NewHumanApprovalWorkflow` builds a graph workflow with
  `workflow.NewEmittingFunctionNode` and `workflow.ResumeOrRequestInput` so the
  workflow pauses until a human response is supplied.
- `propose_follow_up_task` is an ADK function tool with tool confirmation
  enabled, so recursive improvement proposals require explicit approval before
  the tool completes.

## Outside The Agent Team

These responsibilities remain host infrastructure concerns and are not performed
by the agent team:

- Updating `master`, creating branches, allocating worktrees, and enforcing one
  issue branch per PR.
- Container lifecycle, workspace mounting, image builds, cache setup, and
  credential injection.
- Running shell commands or external executables.
- Final PR approval, merge, branch-protection changes, and protected-branch
  pushes.
- Packaging the environment with Nix or containers.

Agent code must not call shell commands or orchestrate external executables.
If validation or implementation needs host execution, the host exposes that
operation as an approved ADK tool, MCP toolset, A2A worker, or direct API
integration with the appropriate role.

## Recursive Improvement

Recursive self-improvement is auditable and bounded. The
`improvement_reviewer_agent` can identify a defect in a completed run and call
`propose_follow_up_task` with:

- Evidence from the run that triggered the proposal.
- The observed defect in prompts, tools, workflows, or evaluations.
- One narrow recommended change.

The proposal does not modify agent instructions, tools, permissions, workflow
definitions, or evaluation criteria. Applying a proposal requires the normal
tracked flow: issue, branch, implementation, validation, PR, and human review.
Self-improvement cannot escalate privileges, bypass branch protection, approve a
PR, or merge a PR.
