package releaseagent

import (
	"context"
	"testing"

	"google.golang.org/adk/v2/tool"
	"google.golang.org/genai"
)

func TestNewTeam_CreatesCoordinator(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test that requires GOOGLE_API_KEY in short mode")
	}
	ctx := context.Background()

	team, err := NewTeam(ctx, Config{
		ModelName:          "gemini-2.0-flash",
		GeminiClientConfig: &genai.ClientConfig{},
	})
	if err != nil {
		t.Fatalf("NewTeam failed: %v", err)
	}

	if team.Name() != CoordinatorName {
		t.Errorf("coordinator name = %q, want %q", team.Name(), CoordinatorName)
	}
}

func TestNewTeam_WithRemoteWorker(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test that requires GOOGLE_API_KEY in short mode")
	}
	ctx := context.Background()

	team, err := NewTeam(ctx, Config{
		ModelName:          "gemini-2.0-flash",
		GeminiClientConfig: &genai.ClientConfig{},
		A2ARemoteWorkers: []A2ARemoteWorker{
			{
				Name:            "remote_impl",
				Description:     "Remote implementation worker",
				AgentCardSource: "http://localhost:9001",
			},
		},
	})
	if err != nil {
		t.Fatalf("NewTeam with remote worker failed: %v", err)
	}

	if team.Name() != CoordinatorName {
		t.Errorf("coordinator name = %q, want %q", team.Name(), CoordinatorName)
	}
}

func TestNewTeam_InvalidModel(t *testing.T) {
	ctx := context.Background()

	_, err := NewTeam(ctx, Config{
		ModelName:          "", // empty model name
		GeminiClientConfig: nil,
	})
	if err == nil {
		t.Fatal("expected error for empty model name, got nil")
	}
}

func TestToolConstructors(t *testing.T) {
	tests := []struct {
		name    string
		builder func() ([]tool.Tool, error)
	}{
		{"intakeTools", newIntakeTools},
		{"implementationTools", newImplementationTools},
		{"validationTools", newValidationTools},
		{"reviewTools", newReviewTools},
		{"statusHandoffTools", newStatusHandoffTools},
		{"improvementTools", newImprovementTools},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tools, err := tt.builder()
			if err != nil {
				t.Fatalf("%s failed: %v", tt.name, err)
			}
			if len(tools) == 0 {
				t.Errorf("%s returned no tools", tt.name)
			}
		})
	}
}

func TestAgentNames(t *testing.T) {
	names := []string{
		CoordinatorName,
		IntakeAgentName,
		ImplementationName,
		ValidationName,
		ReviewName,
		StatusHandoffName,
		ImprovementReviewerName,
	}

	seen := make(map[string]bool)
	for _, n := range names {
		if n == "" {
			t.Error("agent name is empty")
		}
		if seen[n] {
			t.Errorf("duplicate agent name: %q", n)
		}
		seen[n] = true
	}
}

func TestImprovementProposalStructure(t *testing.T) {
	p := ImprovementProposal{
		RunID:      "run-123",
		Category:   "workflow",
		Defect:     "Missing validation step",
		Evidence:   "Run failed at validation stage with no fallback",
		Proposal:   "Add fallback validation for edge cases",
		IssueTitle: "Add fallback validation for edge cases in release workflow",
	}

	if p.RunID == "" {
		t.Error("RunID should not be empty")
	}
	if p.Category == "" {
		t.Error("Category should not be empty")
	}
	if p.Evidence == "" {
		t.Error("Evidence should not be empty")
	}
}


