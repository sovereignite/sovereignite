package kubeapi

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const serviceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"

type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

func NewInCluster() (*Client, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, errors.New("KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT must be set")
	}

	token, err := os.ReadFile(serviceAccountDir + "/token")
	if err != nil {
		return nil, fmt.Errorf("read service account token: %w", err)
	}

	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if caPEM, err := os.ReadFile(serviceAccountDir + "/ca.crt"); err == nil {
		roots.AppendCertsFromPEM(caPEM)
	}

	return &Client{
		baseURL: "https://" + host + ":" + port,
		token:   strings.TrimSpace(string(token)),
		httpClient: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    roots,
		}}},
	}, nil
}

func (c *Client) Get(path string) (map[string]any, error) {
	body, _, err := c.do(http.MethodGet, path, nil, "")
	if err != nil {
		return nil, err
	}
	return decodeMap(body)
}

func (c *Client) List(path string) ([]map[string]any, error) {
	obj, err := c.Get(path)
	if err != nil {
		return nil, err
	}
	items, _ := obj["items"].([]any)
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out, nil
}

func (c *Client) MergePatch(path string, patch map[string]any) error {
	body, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	_, _, err = c.do(http.MethodPatch, path, body, "application/merge-patch+json")
	return err
}

func (c *Client) GetConfigMapValue(namespace, name, key string) (string, error) {
	if key == "" {
		key = "ca.crt"
	}
	obj, err := c.Get("/api/v1/namespaces/" + namespace + "/configmaps/" + name)
	if err != nil {
		return "", err
	}
	data := Map(obj["data"])
	value := StringValue(data[key])
	if strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("configmap %s/%s key %s is empty", namespace, name, key)
	}
	return value, nil
}

func (c *Client) GetSecretValue(namespace, name, key string) (string, error) {
	obj, err := c.Get("/api/v1/namespaces/" + namespace + "/secrets/" + name)
	if err != nil {
		return "", err
	}
	data := Map(obj["data"])
	encoded := StringValue(data[key])
	if encoded == "" {
		return "", fmt.Errorf("secret %s/%s key %s is empty", namespace, name, key)
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("decode secret %s/%s key %s: %w", namespace, name, key, err)
	}
	return strings.TrimSpace(string(decoded)), nil
}

func (c *Client) do(method, path string, body []byte, contentType string) ([]byte, int, error) {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	req, err := http.NewRequest(method, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, resp.StatusCode, fmt.Errorf("%s %s failed: status %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return respBody, resp.StatusCode, nil
}

func decodeMap(body []byte) (map[string]any, error) {
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func Map(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func NestedMap(m map[string]any, path ...string) map[string]any {
	var cur any = m
	for _, p := range path {
		next, ok := cur.(map[string]any)
		if !ok {
			return map[string]any{}
		}
		cur = next[p]
	}
	return Map(cur)
}

func NestedString(m map[string]any, path ...string) string {
	var cur any = m
	for _, p := range path {
		next, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = next[p]
	}
	return StringValue(cur)
}

func StringValue(v any) string {
	switch t := v.(type) {
	case string:
		return t
	default:
		return ""
	}
}

func BoolValue(v any, defaultValue bool) bool {
	switch t := v.(type) {
	case bool:
		return t
	default:
		return defaultValue
	}
}

func Int64Value(v any) int64 {
	switch t := v.(type) {
	case float64:
		return int64(t)
	case int64:
		return t
	case int:
		return int64(t)
	default:
		return 0
	}
}

func StringSlice(v any) []string {
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if s := StringValue(item); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func Name(obj map[string]any) string {
	return NestedString(obj, "metadata", "name")
}

func Namespace(obj map[string]any) string {
	ns := NestedString(obj, "metadata", "namespace")
	if ns == "" {
		return "default"
	}
	return ns
}

func Generation(obj map[string]any) int64 {
	return Int64Value(NestedMap(obj, "metadata")["generation"])
}

func HasCondition(obj map[string]any, conditionType, status string) bool {
	conditions, _ := NestedMap(obj, "status")["conditions"].([]any)
	for _, condition := range conditions {
		c := Map(condition)
		if StringValue(c["type"]) == conditionType && StringValue(c["status"]) == status {
			return true
		}
	}
	return false
}

func ReadyCondition(status, reason, message string) map[string]any {
	return map[string]any{
		"type":               "Ready",
		"status":             status,
		"reason":             reason,
		"message":            message,
		"lastTransitionTime": time.Now().UTC().Format(time.RFC3339),
	}
}
