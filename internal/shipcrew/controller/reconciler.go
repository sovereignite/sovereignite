// Package controller implements the Kubernetes controller for ADK Crew,
// ModelBackend, CrewRun, and MCPServer custom resources.
package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	adkv1alpha1 "github.com/sovereignite/sovereignite/internal/shipcrew/api/v1alpha1"
	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/agent/llmagent"
	"google.golang.org/adk/v2/model"
	"google.golang.org/adk/v2/model/gemini"
	"google.golang.org/adk/v2/model/openaimodel"
	"google.golang.org/adk/v2/runner"
	"google.golang.org/adk/v2/session"
	"google.golang.org/genai"
)

// runnerEntry holds a constructed runner and its root agent for a Crew.
type runnerEntry struct {
	runner  *runner.Runner
	agent   agent.Agent
	appName string
}

// runnerRegistry caches constructed runners per Crew so CrewRun reconcilers
// can execute without reconstructing the agent tree every time.
type runnerRegistry struct {
	mu      sync.RWMutex
	entries map[client.ObjectKey]*runnerEntry
}

func NewRunnerRegistry() *runnerRegistry {
	return &runnerRegistry{entries: make(map[client.ObjectKey]*runnerEntry)}
}

func (r *runnerRegistry) get(key client.ObjectKey) (*runnerEntry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.entries[key]
	return e, ok
}

func (r *runnerRegistry) set(key client.ObjectKey, e *runnerEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries[key] = e
}

func (r *runnerRegistry) delete(key client.ObjectKey) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.entries, key)
}

// ModelBackendReconciler reconciles ModelBackend objects.
type ModelBackendReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=adk.sovereignite.net,resources=modelbackends,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=adk.sovereignite.net,resources=modelbackends/status,verbs=get;update;patch

func (r *ModelBackendReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var mb adkv1alpha1.ModelBackend
	if err := r.Get(ctx, req.NamespacedName, &mb); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	logger.Info("reconciling model backend", "provider", mb.Spec.Provider, "model", mb.Spec.Model)

	apiKey, err := r.resolveAPIKey(ctx, &mb)
	if err != nil {
		return ctrl.Result{}, err
	}

	_, err = buildModel(ctx, &mb, apiKey)
	if err != nil {
		mb.Status.Ready = false
		_ = r.Status().Update(ctx, &mb)
		return ctrl.Result{}, fmt.Errorf("model backend not ready: %w", err)
	}

	mb.Status.Ready = true
	if err := r.Status().Update(ctx, &mb); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *ModelBackendReconciler) resolveAPIKey(ctx context.Context, mb *adkv1alpha1.ModelBackend) (string, error) {
	if mb.Spec.APIKeyRef == nil {
		return "", nil
	}

	var secret corev1.Secret
	key := client.ObjectKey{
		Namespace: mb.Namespace,
		Name:      mb.Spec.APIKeyRef.Name,
	}
	if err := r.Get(ctx, key, &secret); err != nil {
		return "", fmt.Errorf("failed to get secret %s/%s: %w", mb.Namespace, mb.Spec.APIKeyRef.Name, err)
	}

	data, ok := secret.Data[mb.Spec.APIKeyRef.Key]
	if !ok {
		return "", fmt.Errorf("key %q not found in secret %s/%s", mb.Spec.APIKeyRef.Key, mb.Namespace, mb.Spec.APIKeyRef.Name)
	}

	return string(data), nil
}

// CrewReconciler reconciles Crew objects. On each reconciliation it
// constructs the full ADK agent tree and runner, validating that all
// referenced ModelBackends and MCPServers are available.
type CrewReconciler struct {
	client.Client
	Scheme  *runtime.Scheme
	Runners *runnerRegistry
}

// +kubebuilder:rbac:groups=adk.sovereignite.net,resources=crews,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=adk.sovereignite.net,resources=crews/status,verbs=get;update;patch

func (r *CrewReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var crew adkv1alpha1.Crew
	if err := r.Get(ctx, req.NamespacedName, &crew); err != nil {
		r.Runners.delete(req.NamespacedName)
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	logger.Info("reconciling crew", "members", len(crew.Spec.Members))

	// Resolve the default model.
	defaultModel, err := r.resolveModel(ctx, &crew, crew.Spec.ModelRef)
	if err != nil {
		return r.setNotReady(ctx, &crew, fmt.Sprintf("model %q: %v", crew.Spec.ModelRef, err))
	}

	// Build agents bottom-up: first pass builds all members, second
	// pass wires subagent references.
	memberAgents := make(map[string]agent.Agent, len(crew.Spec.Members))
	memberModels := make(map[string]model.LLM, len(crew.Spec.Members))

	for _, m := range crew.Spec.Members {
		llm := defaultModel
		if m.ModelRef != "" {
			var err error
			llm, err = r.resolveModel(ctx, &crew, m.ModelRef)
			if err != nil {
				return r.setNotReady(ctx, &crew, fmt.Sprintf("member %q model %q: %v", m.Name, m.ModelRef, err))
			}
		}
		memberModels[m.Name] = llm
	}

	for _, m := range crew.Spec.Members {
		// Resolve subagent references.
		var subAgents []agent.Agent
		for _, ref := range m.SubAgents {
			sub, ok := memberAgents[ref]
			if !ok {
				return r.setNotReady(ctx, &crew, fmt.Sprintf("member %q references unknown subagent %q", m.Name, ref))
			}
			subAgents = append(subAgents, sub)
		}

		cfg := llmagent.Config{
			Name:        m.Name,
			Description: m.Description,
			Model:       memberModels[m.Name],
			Mode:        resolveMode(m.Mode),
			Instruction: m.Instruction,
			SubAgents:   subAgents,
			OutputKey:   m.OutputKey,
		}

		if m.GenerateContentConfig != nil {
			var gcc genai.GenerateContentConfig
			if err := json.Unmarshal(m.GenerateContentConfig.Raw, &gcc); err != nil {
				return r.setNotReady(ctx, &crew, fmt.Sprintf("member %q generateContentConfig: %v", m.Name, err))
			}
			cfg.GenerateContentConfig = &gcc
		}

		if m.InputSchema != nil {
			var s genai.Schema
			if err := json.Unmarshal(m.InputSchema.Raw, &s); err != nil {
				return r.setNotReady(ctx, &crew, fmt.Sprintf("member %q inputSchema: %v", m.Name, err))
			}
			cfg.InputSchema = &s
		}

		if m.OutputSchema != nil {
			var s genai.Schema
			if err := json.Unmarshal(m.OutputSchema.Raw, &s); err != nil {
				return r.setNotReady(ctx, &crew, fmt.Sprintf("member %q outputSchema: %v", m.Name, err))
			}
			cfg.OutputSchema = &s
		}

		if m.IncludeContents != nil {
			cfg.IncludeContents = llmagent.IncludeContents(*m.IncludeContents)
		}

		if m.DisallowTransferToParent != nil {
			cfg.DisallowTransferToParent = *m.DisallowTransferToParent
		}
		if m.DisallowTransferToPeers != nil {
			cfg.DisallowTransferToPeers = *m.DisallowTransferToPeers
		}

		a, err := llmagent.New(cfg)
		if err != nil {
			return r.setNotReady(ctx, &crew, fmt.Sprintf("member %q: %v", m.Name, err))
		}
		memberAgents[m.Name] = a
	}

	// The root agent is the first member (skipper convention).
	if len(crew.Spec.Members) == 0 {
		return r.setNotReady(ctx, &crew, "no members defined")
	}
	rootName := crew.Spec.Members[0].Name
	rootAgent, ok := memberAgents[rootName]
	if !ok {
		return r.setNotReady(ctx, &crew, fmt.Sprintf("root agent %q not found", rootName))
	}

	// Build runner with in-memory session service.
	appName := crew.Spec.AppName
	if appName == "" {
		appName = crew.Name
	}

	run, err := runner.New(runner.Config{
		AppName:           appName,
		Agent:             rootAgent,
		SessionService:    session.InMemoryService(),
		AutoCreateSession: true,
	})
	if err != nil {
		return r.setNotReady(ctx, &crew, fmt.Sprintf("runner: %v", err))
	}

	r.Runners.set(req.NamespacedName, &runnerEntry{
		runner:  run,
		agent:   rootAgent,
		appName: appName,
	})

	crew.Status.Ready = true
	crew.Status.Conditions = nil
	if err := r.Status().Update(ctx, &crew); err != nil {
		return ctrl.Result{}, err
	}

	logger.Info("crew ready", "appName", appName, "members", len(crew.Spec.Members))
	return ctrl.Result{}, nil
}

func (r *CrewReconciler) resolveModel(ctx context.Context, crew *adkv1alpha1.Crew, ref string) (model.LLM, error) {
	var mb adkv1alpha1.ModelBackend
	key := client.ObjectKey{Namespace: crew.Namespace, Name: ref}
	if err := r.Get(ctx, key, &mb); err != nil {
		return nil, fmt.Errorf("model backend %q not found: %w", ref, err)
	}
	if !mb.Status.Ready {
		return nil, fmt.Errorf("model backend %q not ready", ref)
	}
	apiKey, err := r.resolveAPIKeyFromRef(ctx, crew.Namespace, mb.Spec.APIKeyRef)
	if err != nil {
		return nil, err
	}
	return buildModel(ctx, &mb, apiKey)
}

func (r *CrewReconciler) resolveAPIKeyFromRef(ctx context.Context, namespace string, ref *adkv1alpha1.SecretKeyRef) (string, error) {
	if ref == nil {
		return "", nil
	}
	var secret corev1.Secret
	key := client.ObjectKey{Namespace: namespace, Name: ref.Name}
	if err := r.Get(ctx, key, &secret); err != nil {
		return "", fmt.Errorf("secret %s/%s: %w", namespace, ref.Name, err)
	}
	data, ok := secret.Data[ref.Key]
	if !ok {
		return "", fmt.Errorf("key %q not in secret %s/%s", ref.Key, namespace, ref.Name)
	}
	return string(data), nil
}

func (r *CrewReconciler) setNotReady(ctx context.Context, crew *adkv1alpha1.Crew, msg string) (ctrl.Result, error) {
	crew.Status.Ready = false
	_ = r.Status().Update(ctx, crew)
	return ctrl.Result{}, fmt.Errorf("%s", msg)
}

func (r *CrewReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&adkv1alpha1.Crew{}).
		Complete(r)
}

// CrewRunReconciler reconciles CrewRun objects. It resolves the Crew's
// runner from the registry and executes runner.Run().
type CrewRunReconciler struct {
	client.Client
	Scheme  *runtime.Scheme
	Runners *runnerRegistry
}

// +kubebuilder:rbac:groups=adk.sovereignite.net,resources=crewruns,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=adk.sovereignite.net,resources=crewruns/status,verbs=get;update;patch

func (r *CrewRunReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var run adkv1alpha1.CrewRun
	if err := r.Get(ctx, req.NamespacedName, &run); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Skip if already terminal.
	if run.Status.Phase == adkv1alpha1.CrewRunPhaseSucceeded ||
		run.Status.Phase == adkv1alpha1.CrewRunPhaseFailed {
		return ctrl.Result{}, nil
	}

	// Mark running.
	run.Status.Phase = adkv1alpha1.CrewRunPhaseRunning
	if err := r.Status().Update(ctx, &run); err != nil {
		return ctrl.Result{}, err
	}

	// Resolve runner from registry.
	crewKey := client.ObjectKey{Namespace: run.Namespace, Name: run.Spec.CrewRef}
	entry, ok := r.Runners.get(crewKey)
	if !ok {
		run.Status.Phase = adkv1alpha1.CrewRunPhaseFailed
		_ = r.Status().Update(ctx, &run)
		return ctrl.Result{}, fmt.Errorf("crew %q runner not ready", run.Spec.CrewRef)
	}

	// Build genai.Content from the message spec.
	msg := buildContent(&run.Spec.Message)

	// Resolve session ID.
	sessionID := run.Spec.SessionID
	if sessionID == "" {
		sessionID = fmt.Sprintf("%s/%s", run.Namespace, run.Name)
	}
	run.Status.SessionID = sessionID

	// Build RunConfig.
	runCfg := agent.RunConfig{}
	if run.Spec.StreamingMode != nil && *run.Spec.StreamingMode == adkv1alpha1.StreamingModeSSE {
		runCfg.StreamingMode = agent.StreamingModeSSE
	}
	if run.Spec.SaveInputBlobsAsArtifacts != nil {
		runCfg.SaveInputBlobsAsArtifacts = *run.Spec.SaveInputBlobsAsArtifacts
	}

	logger.Info("executing crew run", "crew", run.Spec.CrewRef, "userID", run.Spec.UserID, "sessionID", sessionID)

	// Execute runner.Run() and collect events.
	var events []runtime.RawExtension
	for event, err := range entry.runner.Run(ctx, run.Spec.UserID, sessionID, msg, runCfg) {
		if err != nil {
			logger.Error(err, "runner error")
			run.Status.Phase = adkv1alpha1.CrewRunPhaseFailed
			_ = r.Status().Update(ctx, &run)
			return ctrl.Result{}, err
		}
		if event != nil {
			raw, err := json.Marshal(event)
			if err != nil {
				logger.Error(err, "failed to marshal event")
				continue
			}
			events = append(events, runtime.RawExtension{Raw: raw})
		}
	}

	run.Status.Events = toAPIExtensionsJSON(events)
	run.Status.Phase = adkv1alpha1.CrewRunPhaseSucceeded
	if err := r.Status().Update(ctx, &run); err != nil {
		return ctrl.Result{}, err
	}

	logger.Info("crew run completed", "crew", run.Spec.CrewRef, "events", len(events))
	return ctrl.Result{}, nil
}

func (r *CrewRunReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&adkv1alpha1.CrewRun{}).
		Complete(r)
}

// --- helpers ---

func buildModel(ctx context.Context, mb *adkv1alpha1.ModelBackend, apiKey string) (model.LLM, error) {
	switch mb.Spec.Provider {
	case adkv1alpha1.ProviderGemini:
		if apiKey == "" {
			return nil, fmt.Errorf("gemini provider requires apiKeyRef")
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

func resolveMode(m adkv1alpha1.AgentMode) llmagent.Mode {
	switch m {
	case adkv1alpha1.ModeChat:
		return llmagent.ModeChat
	case adkv1alpha1.ModeTask:
		return llmagent.ModeTask
	case adkv1alpha1.ModeSingleTurn:
		return llmagent.ModeSingleTurn
	default:
		return llmagent.ModeChat
	}
}

func buildContent(msg *adkv1alpha1.MessageContent) *genai.Content {
	if msg.Parts != nil {
		var parts []*genai.Part
		if err := json.Unmarshal(msg.Parts.Raw, &parts); err == nil {
			return &genai.Content{Role: "user", Parts: parts}
		}
	}
	return genai.NewContentFromText(msg.Text, genai.RoleUser)
}

func toAPIExtensionsJSON(events []runtime.RawExtension) []apiextensionsv1.JSON {
	out := make([]apiextensionsv1.JSON, len(events))
	for i, e := range events {
		out[i] = apiextensionsv1.JSON{Raw: e.Raw}
	}
	return out
}

// SetupWithManager registers the ModelBackend controller.
func (r *ModelBackendReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&adkv1alpha1.ModelBackend{}).
		Complete(r)
}
