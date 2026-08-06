// Command shipcrew runs the Sovereignite release task agent crew.
//
// Usage:
//
//	shipcrew --issue 26
//	shipcrew --issue 26 --backend openai --model gpt-4o
//	shipcrew --backend ollama --model llama3.1
//	shipcrew --config crew.yaml --issue 26
//	shipcrew --serve --port 8080
//	shipcrew controller
//
// Backends:
//
//	gemini  — Google AI Studio (GOOGLE_API_KEY) or Vertex AI (GOOGLE_GENAI_USE_VERTEXAI=1)
//	openai  — OpenAI (OPENAI_API_KEY)
//	ollama  — Local Ollama (OPENAI_BASE_URL=http://localhost:11434/v1)
//
// Config mode:
//
//	shipcrew --config crew.yaml --issue 26
//
// The config file contains ModelBackend and Crew CRD resources (adk.sovereignite.net/v1alpha1).
package main

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"

	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/artifact"
	"google.golang.org/adk/v2/cmd/launcher"
	"google.golang.org/adk/v2/cmd/launcher/web"
	"google.golang.org/adk/v2/cmd/launcher/web/a2a"
	"google.golang.org/adk/v2/model"
	"google.golang.org/adk/v2/model/gemini"
	"google.golang.org/adk/v2/model/openaimodel"
	"google.golang.org/adk/v2/runner"
	"google.golang.org/adk/v2/session"
	"google.golang.org/genai"
	"k8s.io/apimachinery/pkg/util/yaml"

	adkv1alpha1 "github.com/sovereignite/sovereignite/internal/shipcrew/api/v1alpha1"
	"github.com/sovereignite/sovereignite/internal/shipcrew"
)

func main() {
	issue := flag.Int("issue", 0, "GitHub issue number to process")
	backend := flag.String("backend", "gemini", "Model backend: gemini, openai, ollama")
	modelName := flag.String("model", "", "Model name (default depends on backend)")
	configPath := flag.String("config", "", "Path to CRD YAML config (ModelBackend + Crew)")
	serve := flag.Bool("serve", false, "Run as A2A server instead of one-shot CLI")
	port := flag.Int("port", 8080, "Port for A2A server mode")
	flag.Parse()

	if len(os.Args) > 1 && os.Args[1] == "controller" {
		runController()
		return
	}

	if *issue == 0 && !*serve && *configPath == "" {
		fmt.Fprintln(os.Stderr, "usage: shipcrew --issue <number> [--backend gemini|openai|ollama] [--model <model>]")
		fmt.Fprintln(os.Stderr, "       shipcrew --config crew.yaml --issue <number>")
		fmt.Fprintln(os.Stderr, "       shipcrew --serve [--port <port>] [--backend <backend>] [--model <model>]")
		fmt.Fprintln(os.Stderr, "       shipcrew controller")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "backends:")
		fmt.Fprintln(os.Stderr, "  gemini   GOOGLE_API_KEY or GOOGLE_GENAI_USE_VERTEXAI=1")
		fmt.Fprintln(os.Stderr, "  openai   OPENAI_API_KEY")
		fmt.Fprintln(os.Stderr, "  ollama   OPENAI_BASE_URL=http://localhost:11434/v1")
		os.Exit(1)
	}

	ctx := context.Background()

	var llm model.LLM
	var err error

	if *configPath != "" {
		llm, err = buildModelFromConfig(ctx, *configPath)
	} else {
		llm, err = buildModel(ctx, *backend, *modelName)
	}
	if err != nil {
		log.Fatal(err)
	}

	skipper, err := shipcrew.NewCrew(ctx, shipcrew.CrewConfig{
		Model: llm,
	})
	if err != nil {
		log.Fatalf("Failed to create crew: %v", err)
	}

	if *serve {
		runServer(ctx, skipper, *port)
		return
	}

	if *issue == 0 {
		log.Fatal("--issue is required when not in --serve mode")
	}

	runCLI(ctx, skipper, *issue)
}

// buildModelFromConfig reads a CRD YAML file and builds the model from the
// first ModelBackend resource found.
func buildModelFromConfig(ctx context.Context, path string) (model.LLM, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()

	docs := splitYAML(f)
	for _, doc := range docs {
		var mb adkv1alpha1.ModelBackend
		if err := yaml.Unmarshal(doc, &mb); err != nil {
			continue
		}
		if mb.Kind == "ModelBackend" && mb.APIVersion == "adk.sovereignite.net/v1alpha1" {
			return buildModelFromBackend(ctx, &mb)
		}
	}

	return nil, fmt.Errorf("no ModelBackend found in %s", path)
}

func buildModelFromBackend(ctx context.Context, mb *adkv1alpha1.ModelBackend) (model.LLM, error) {
	switch mb.Spec.Provider {
	case adkv1alpha1.ProviderGemini:
		apiKey := os.Getenv("GOOGLE_API_KEY")
		if apiKey == "" {
			return nil, fmt.Errorf("gemini provider requires GOOGLE_API_KEY")
		}
		return gemini.NewModel(ctx, mb.Spec.Model, &genai.ClientConfig{APIKey: apiKey})
	case adkv1alpha1.ProviderOpenAI:
		return openaimodel.NewModel(ctx, mb.Spec.Model, &openaimodel.ClientConfig{
			BaseURL: mb.Spec.BaseURL,
		})
	case adkv1alpha1.ProviderOllama:
		baseURL := mb.Spec.BaseURL
		if baseURL == "" {
			baseURL = "http://localhost:11434/v1"
		}
		return openaimodel.NewModel(ctx, mb.Spec.Model, &openaimodel.ClientConfig{
			BaseURL: baseURL,
		})
	default:
		return nil, fmt.Errorf("unknown provider %q", mb.Spec.Provider)
	}
}

func splitYAML(r io.Reader) [][]byte {
	var docs [][]byte
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	var current bytes.Buffer
	for scanner.Scan() {
		line := scanner.Text()
		if line == "---" {
			if current.Len() > 0 {
				docs = append(docs, current.Bytes())
				current.Reset()
			}
			continue
		}
		current.WriteString(line)
		current.WriteByte('\n')
	}
	if current.Len() > 0 {
		docs = append(docs, current.Bytes())
	}
	return docs
}

func buildModel(ctx context.Context, backend, modelName string) (model.LLM, error) {
	switch backend {
	case "gemini":
		return buildGeminiModel(ctx, modelName)
	case "openai":
		return buildOpenAIModel(ctx, modelName, "")
	case "ollama":
		return buildOpenAIModel(ctx, modelName, "http://localhost:11434/v1")
	default:
		return nil, fmt.Errorf("unknown backend %q (supported: gemini, openai, ollama)", backend)
	}
}

func buildGeminiModel(ctx context.Context, modelName string) (model.LLM, error) {
	if modelName == "" {
		modelName = "gemini-2.0-flash"
	}

	if os.Getenv("GOOGLE_GENAI_USE_VERTEXAI") == "1" {
		project := os.Getenv("GCLOUD_PROJECT")
		if project == "" {
			project = os.Getenv("GOOGLE_CLOUD_PROJECT")
		}
		location := os.Getenv("GOOGLE_CLOUD_LOCATION")
		if location == "" {
			location = os.Getenv("GOOGLE_CLOUD_REGION")
		}
		if project == "" || location == "" {
			return nil, fmt.Errorf("vertex ai requires GCLOUD_PROJECT and GOOGLE_CLOUD_LOCATION")
		}
		return gemini.NewModel(ctx, modelName, &genai.ClientConfig{
			Backend:  genai.BackendVertexAI,
			Project:  project,
			Location: location,
		})
	}

	apiKey := os.Getenv("GOOGLE_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("gemini backend requires GOOGLE_API_KEY (or set GOOGLE_GENAI_USE_VERTEXAI=1 for Vertex AI)")
	}
	return gemini.NewModel(ctx, modelName, &genai.ClientConfig{APIKey: apiKey})
}

func buildOpenAIModel(ctx context.Context, modelName, baseURL string) (model.LLM, error) {
	if modelName == "" {
		modelName = "gpt-4o-mini"
	}
	return openaimodel.NewModel(ctx, modelName, &openaimodel.ClientConfig{
		BaseURL: baseURL,
	})
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

func runController() {
	log.Println("controller mode not yet implemented — use --config for local CRD execution")
	os.Exit(1)
}
