// Package controller implements the Kubernetes controller for ADK Crew and
// ModelBackend custom resources.
package controller

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	adkv1alpha1 "github.com/sovereignite/sovereignite/internal/shipcrew/api/v1alpha1"
	"google.golang.org/adk/v2/model"
	"google.golang.org/adk/v2/model/gemini"
	"google.golang.org/adk/v2/model/openaimodel"
	"google.golang.org/genai"
)

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

	// Resolve API key from secret if referenced.
	apiKey, err := r.resolveAPIKey(ctx, &mb)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Validate that the backend can be constructed.
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

// CrewReconciler reconciles Crew objects.
type CrewReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=adk.sovereignite.net,resources=crews,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=adk.sovereignite.net,resources=crews/status,verbs=get;update;patch

func (r *CrewReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var crew adkv1alpha1.Crew
	if err := r.Get(ctx, req.NamespacedName, &crew); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	logger.Info("reconciling crew", "members", len(crew.Spec.Members))

	// Resolve the referenced ModelBackend.
	var mb adkv1alpha1.ModelBackend
	mbKey := client.ObjectKey{
		Namespace: crew.Namespace,
		Name:      crew.Spec.ModelRef,
	}
	if err := r.Get(ctx, mbKey, &mb); err != nil {
		crew.Status.Ready = false
		_ = r.Status().Update(ctx, &crew)
		return ctrl.Result{}, fmt.Errorf("model backend %q not found: %w", crew.Spec.ModelRef, err)
	}

	if !mb.Status.Ready {
		crew.Status.Ready = false
		_ = r.Status().Update(ctx, &crew)
		return ctrl.Result{}, fmt.Errorf("model backend %q not ready", crew.Spec.ModelRef)
	}

	crew.Status.Ready = true
	if err := r.Status().Update(ctx, &crew); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager registers the controllers with the manager.
func (r *ModelBackendReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&adkv1alpha1.ModelBackend{}).
		Complete(r)
}

func (r *CrewReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&adkv1alpha1.Crew{}).
		Complete(r)
}

// buildModel constructs a model.LLM from a ModelBackend spec.
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
