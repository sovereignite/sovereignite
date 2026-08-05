// Command shipcrew runs the Sovereignite release task agent crew.
//
// Usage:
//
//	shipcrew --issue 26
//	shipcrew --issue 26 --model gemini-2.0-flash
//	shipcrew --serve --port 8080
//
// The crew uses ADK collaboration modes, delegation, tool confirmation for
// human approval gates, and optional A2A remote crew members.
//
// Set GOOGLE_API_KEY in the environment for the Gemini model backend.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"

	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/artifact"
	"google.golang.org/adk/v2/cmd/launcher"
	"google.golang.org/adk/v2/cmd/launcher/web"
	"google.golang.org/adk/v2/cmd/launcher/web/a2a"
	"google.golang.org/adk/v2/runner"
	"google.golang.org/adk/v2/session"
	"google.golang.org/genai"

	"github.com/sovereignite/sovereignite/internal/shipcrew"
)

func main() {
	issue := flag.Int("issue", 0, "GitHub issue number to process")
	model := flag.String("model", "gemini-2.0-flash", "ADK model identifier")
	serve := flag.Bool("serve", false, "Run as A2A server instead of one-shot CLI")
	port := flag.Int("port", 8080, "Port for A2A server mode")
	flag.Parse()

	if *issue == 0 && !*serve {
		fmt.Fprintln(os.Stderr, "usage: shipcrew --issue <number> [--model <model>]")
		fmt.Fprintln(os.Stderr, "       shipcrew --serve [--port <port>] [--model <model>]")
		os.Exit(1)
	}

	ctx := context.Background()

	apiKey := os.Getenv("GOOGLE_API_KEY")
	if apiKey == "" {
		log.Fatal("GOOGLE_API_KEY environment variable is required. Get a key from https://ai.google.dev/gemini-api/docs/api-key")
	}

	skipper, err := shipcrew.NewCrew(ctx, shipcrew.CrewConfig{
		ModelName:          *model,
		GeminiClientConfig: &genai.ClientConfig{APIKey: apiKey},
	})
	if err != nil {
		log.Fatalf("Failed to create crew: %v", err)
	}

	if *serve {
		runServer(ctx, skipper, *port)
		return
	}

	runCLI(ctx, skipper, *issue)
}

func runCLI(ctx context.Context, skipper agent.Agent, issue int) {
	sessionService := session.InMemoryService()
	artifactService := artifact.InMemoryService()

	sessionID := fmt.Sprintf("issue-%d", issue)
	_, err := sessionService.Create(ctx, &session.CreateRequest{
		AppName:   skipper.Name(),
		UserID:    "cli",
		SessionID: sessionID,
	})
	if err != nil {
		log.Fatalf("Failed to create session: %v", err)
	}

	r, err := runner.New(runner.Config{
		AppName:         skipper.Name(),
		Agent:           skipper,
		SessionService:  sessionService,
		ArtifactService: artifactService,
	})
	if err != nil {
		log.Fatalf("Failed to create runner: %v", err)
	}

	task := fmt.Sprintf("Process GitHub issue #%d. Read the issue, extract requirements, implement, validate, review, and report.", issue)
	fmt.Printf("skipper: %s\n\n", task)

	inputContent := genai.NewContentFromText(task, genai.RoleUser)
	for event, err := range r.Run(ctx, "cli", sessionID, inputContent, agent.RunConfig{
		StreamingMode: agent.StreamingModeNone,
	}) {
		if err != nil {
			log.Printf("error: %v", err)
			continue
		}
		if event.Content != nil {
			for _, part := range event.Content.Parts {
				if part.Text != "" {
					fmt.Printf("%s: %s\n", event.Author, part.Text)
				}
				if part.FunctionCall != nil {
					fmt.Printf("%s → %s(%v)\n", event.Author, part.FunctionCall.Name, part.FunctionCall.Args)
				}
				if part.FunctionResponse != nil {
					fmt.Printf("%s ← %s: %v\n", event.Author, part.FunctionResponse.Name, part.FunctionResponse.Response)
				}
			}
		}
	}
}

func runServer(ctx context.Context, skipper agent.Agent, port int) {
	webLauncher := web.NewLauncher(a2a.NewLauncher())
	_, err := webLauncher.Parse([]string{
		"--port", strconv.Itoa(port),
		"a2a", "--a2a_agent_url", "http://localhost:" + strconv.Itoa(port),
	})
	if err != nil {
		log.Fatalf("launcher parse: %v", err)
	}

	config := &launcher.Config{
		AgentLoader:    agent.NewSingleLoader(skipper),
		SessionService: session.InMemoryService(),
	}

	log.Printf("shipcrew serving on port %d", port)
	if err := webLauncher.Run(ctx, config); err != nil {
		log.Fatalf("server: %v", err)
	}
}
