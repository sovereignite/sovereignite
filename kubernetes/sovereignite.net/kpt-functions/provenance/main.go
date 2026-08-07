// Copyright 2026 SovereignIT Foundation
// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Kptfile represents the structure of a Kptfile
type Kptfile struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name        string            `yaml:"name"`
		Annotations map[string]string `yaml:"annotations"`
	} `yaml:"metadata"`
	Info struct {
		Description string   `yaml:"description"`
		Keywords    []string `yaml:"keywords"`
		Site        string   `yaml:"site"`
		Emails      []string `yaml:"emails"`
		License     string   `yaml:"license"`
	} `yaml:"info"`
	Upstream struct {
		Type string `yaml:"type"`
		Git  struct {
			Repo      string `yaml:"repo"`
			Directory string `yaml:"directory"`
			Ref       string `yaml:"ref"`
		} `yaml:"git"`
	} `yaml:"upstream"`
	UpstreamLock struct {
		Type string `yaml:"type"`
		Git  struct {
			Repo      string `yaml:"repo"`
			Directory string `yaml:"directory"`
			Ref       string `yaml:"ref"`
			Commit    string `yaml:"commit"`
		} `yaml:"git"`
	} `yaml:"upstreamLock"`
	Pipeline struct {
		Validators []struct {
			Image  string                 `yaml:"image"`
			Name   string                 `yaml:"name"`
			Config map[string]interface{} `yaml:"configMap"`
		} `yaml:"validators"`
		Mutators []struct {
			Image  string                 `yaml:"image"`
			Name   string                 `yaml:"name"`
			Config map[string]interface{} `yaml:"configMap"`
		} `yaml:"mutators"`
	} `yaml:"pipeline"`
}

// ProvenanceReport represents the output provenance report
type ProvenanceReport struct {
	APIVersion string            `yaml:"apiVersion"`
	Kind       string            `yaml:"kind"`
	Metadata   map[string]string `yaml:"metadata"`
	Data       map[string]string `yaml:"data"`
}

func main() {
	// Read all KRM resources from stdin
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
		os.Exit(1)
	}

	// Split input into multiple YAML documents
	decoder := yaml.NewDecoder(bytes.NewReader(input))
	var resources []map[string]interface{}

	for {
		var doc map[string]interface{}
		err := decoder.Decode(&doc)
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error decoding YAML: %v\n", err)
			os.Exit(1)
		}
		if doc != nil {
			resources = append(resources, doc)
		}
	}

	// Find the Kptfile
	var kptfile *Kptfile
	for _, doc := range resources {
		kind, ok := doc["kind"].(string)
		if !ok || kind != "Kptfile" {
			continue
		}

		// Convert to Kptfile struct
		yamlBytes, err := yaml.Marshal(doc)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling Kptfile: %v\n", err)
			os.Exit(1)
		}

		kptfile = &Kptfile{}
		if err := yaml.Unmarshal(yamlBytes, kptfile); err != nil {
			fmt.Fprintf(os.Stderr, "Error unmarshaling Kptfile: %v\n", err)
			os.Exit(1)
		}
		break
	}

	if kptfile == nil {
		fmt.Fprintf(os.Stderr, "No Kptfile found in input\n")
		os.Exit(1)
	}

	// Generate provenance report
	report := ProvenanceReport{
		APIVersion: "v1",
		Kind:       "ConfigMap",
		Metadata: map[string]string{
			"name":      "provenance-report",
			"namespace": "default",
		},
		Data: map[string]string{
			"package-name":    kptfile.Metadata.Name,
			"upstream-repo":   kptfile.Upstream.Git.Repo,
			"upstream-dir":    kptfile.Upstream.Git.Directory,
			"upstream-ref":    kptfile.Upstream.Git.Ref,
			"upstream-commit": kptfile.UpstreamLock.Git.Commit,
			"license":         kptfile.Info.License,
			"site":            kptfile.Info.Site,
			"emails":          fmt.Sprintf("%v", kptfile.Info.Emails),
			"keywords":        fmt.Sprintf("%v", kptfile.Info.Keywords),
			"validators":      formatValidators(kptfile.Pipeline.Validators),
			"mutators":        formatMutators(kptfile.Pipeline.Mutators),
			"resource-count":  fmt.Sprintf("%d", len(resources)-1), // Exclude Kptfile itself
			"generated-at":    time.Now().UTC().Format(time.RFC3339),
		},
	}

	// Add local-config annotation
	report.Metadata["annotations"] = "config.kubernetes.io/local-config: true"

	// Output the report with 2-space indent (repo convention)
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(report); err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling report: %v\n", err)
		os.Exit(1)
	}
	if err := enc.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "Error closing encoder: %v\n", err)
		os.Exit(1)
	}

	fmt.Print(buf.String())
}

func formatValidators(validators []struct {
	Image  string                 `yaml:"image"`
	Name   string                 `yaml:"name"`
	Config map[string]interface{} `yaml:"configMap"`
}) string {
	if len(validators) == 0 {
		return "none"
	}

	var result string
	for i, v := range validators {
		if i > 0 {
			result += "; "
		}
		result += fmt.Sprintf("%s (%s)", v.Name, v.Image)
	}
	return result
}

func formatMutators(mutators []struct {
	Image  string                 `yaml:"image"`
	Name   string                 `yaml:"name"`
	Config map[string]interface{} `yaml:"configMap"`
}) string {
	if len(mutators) == 0 {
		return "none"
	}

	var result string
	for i, m := range mutators {
		if i > 0 {
			result += "; "
		}
		result += fmt.Sprintf("%s (%s)", m.Name, m.Image)
	}
	return result
}
