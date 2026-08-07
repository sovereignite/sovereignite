package shipcrew

import (
	"context"
	"testing"

	"google.golang.org/adk/v2/model"
	"google.golang.org/adk/v2/tool"
)

func TestNewCrew_NilModel(t *testing.T) {
	ctx := context.Background()

	_, err := NewCrew(ctx, CrewConfig{
		Model: nil,
	})
	if err == nil {
		t.Fatal("expected error for nil model, got nil")
	}
}

func TestToolConstructors(t *testing.T) {
	tests := []struct {
		name    string
		builder func() ([]tool.Tool, error)
	}{
		{"scoutTools", newScoutTools},
		{"builderTools", newBuilderTools},
		{"proverTools", newProverTools},
		{"criticTools", newCriticTools},
		{"heraldTools", newHeraldTools},
		{"retroTools", newRetroTools},
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
		SkipperName,
		ScoutName,
		BuilderName,
		ProverName,
		CriticName,
		HeraldName,
		RetroName,
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

// Ensure the model.LLM interface is referenced (avoids unused import).
var _ model.LLM
