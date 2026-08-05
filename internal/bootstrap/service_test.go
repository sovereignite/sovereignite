// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package bootstrap

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"
)

func TestConfigurationRequiresEveryAuthorityContractAndPinnedVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Configuration)
	}{
		{
			name: "missing topology",
			mutate: func(config *Configuration) {
				config.Authority.KubernetesTopology = Artifact{}
			},
		},
		{
			name: "missing TPM inventory",
			mutate: func(config *Configuration) {
				config.Authority.TPMKeyInventory = Artifact{}
			},
		},
		{
			name: "missing issuer hierarchy",
			mutate: func(config *Configuration) {
				config.Authority.IssuerHierarchy = Artifact{}
			},
		},
		{
			name: "missing ingress token flow",
			mutate: func(config *Configuration) {
				config.Authority.IngressTokenFlow = Artifact{}
			},
		},
		{
			name: "missing compatibility matrix",
			mutate: func(config *Configuration) {
				config.Authority.Compatibility = Artifact{}
			},
		},
		{
			name: "moving Kubernetes version",
			mutate: func(config *Configuration) {
				config.Versions.Kubernetes = "latest"
				config.Artifacts.Kubelet.Version = "latest"
				config.Artifacts.ControlPlane.Version = "latest"
				config.Artifacts.Cluster.Version = "latest"
			},
		},
		{
			name: "missing Dex version",
			mutate: func(config *Configuration) {
				config.Versions.Dex = ""
			},
		},
		{
			name: "missing TPM Device Key reference",
			mutate: func(config *Configuration) {
				config.TPMDeviceKeyReference = ""
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config := validTestConfiguration()
			test.mutate(&config)
			if _, err := config.validate(); err == nil {
				t.Fatal("configuration unexpectedly validated")
			}
		})
	}
}

func TestConfigurationRequiresCanonicalInjectedIPv6ULA48(t *testing.T) {
	t.Parallel()

	tests := []netip.Prefix{
		{},
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("2001:db8::/48"),
		netip.MustParsePrefix("fd18:4f1c:14d::/64"),
		netip.MustParsePrefix("fd18:4f1c:14d:1::/48"),
	}
	for _, prefix := range tests {
		config := validTestConfiguration()
		config.ULA = prefix
		if _, err := config.validate(); err == nil {
			t.Fatalf("configuration accepted ULA %v", prefix)
		}
	}
}

func TestConfigurationRejectsDigestMutationAndWrongVersion(t *testing.T) {
	t.Parallel()

	t.Run("digest mutation", func(t *testing.T) {
		t.Parallel()
		config := validTestConfiguration()
		config.Artifacts.Calico.Content[0] ^= 0xff
		if _, err := config.validate(); err == nil {
			t.Fatal("configuration accepted mutated artifact bytes")
		}
	})
	t.Run("wrong component version", func(t *testing.T) {
		t.Parallel()
		config := validTestConfiguration()
		config.Artifacts.Dex.Version = "v2.44.0"
		if _, err := config.validate(); err == nil {
			t.Fatal("configuration accepted a Dex version mismatch")
		}
	})
	t.Run("uppercase digest", func(t *testing.T) {
		t.Parallel()
		config := validTestConfiguration()
		config.Artifacts.Istio.SHA256 = strings.ToUpper(
			config.Artifacts.Istio.SHA256,
		)
		if _, err := config.validate(); err == nil {
			t.Fatal("configuration accepted a non-canonical digest")
		}
	})
}

func TestConfigurationRejectsPrivateKeysKubeadmAndCustomCRDs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "private key",
			content: "-----BEGIN PRIVATE KEY-----\ncanary\n-----END PRIVATE KEY-----\n",
		},
		{
			name:    "kubeadm",
			content: "command: kubeadm init\n",
		},
		{
			name: "Sovereignite CRD",
			content: "apiVersion: apiextensions.k8s.io/v1\n" +
				"kind: CustomResourceDefinition\n" +
				"metadata:\n  name: identities.github.com/sovereignite/sovereignite\n",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config := validTestConfiguration()
			config.Artifacts.Cluster = testArtifact(
				ArtifactCluster,
				config.Versions.Kubernetes,
				test.content,
			)
			if _, err := config.validate(); err == nil {
				t.Fatal("configuration accepted forbidden artifact content")
			}
		})
	}
}

func TestConfigurationRequiresSPIREArtifactToUseInjectedTPMReference(t *testing.T) {
	t.Parallel()

	config := validTestConfiguration()
	config.Artifacts.SPIRE = testArtifact(
		ArtifactSPIRE,
		config.Versions.SPIRE,
		"plugin = tpm_devid\nreference = a-different-handle\n",
	)
	if _, err := config.validate(); err == nil {
		t.Fatal("configuration accepted an unbound SPIRE TPM reference")
	}
}

func TestConfigurationDigestBindsEveryAuthorityAndArtifactInput(t *testing.T) {
	t.Parallel()

	base := validTestConfiguration()
	baseDigest, err := base.validate()
	if err != nil {
		t.Fatal(err)
	}
	mutations := []func(*Configuration){
		func(config *Configuration) {
			config.ULA = netip.MustParsePrefix("fdff:1:2::/48")
		},
		func(config *Configuration) {
			config.TPMDeviceKeyReference = "tpm-device-key:0x81010041"
			config.Artifacts.SPIRE = testArtifact(
				ArtifactSPIRE,
				config.Versions.SPIRE,
				"reference = tpm-device-key:0x81010041\n",
			)
		},
		func(config *Configuration) {
			config.Artifacts.Dex = testArtifact(
				ArtifactDex,
				config.Versions.Dex,
				"different Dex configuration\n",
			)
		},
		func(config *Configuration) {
			config.Authority.Compatibility = testArtifact(
				ArtifactCompatibility,
				"compatibility-r2",
				"different compatibility matrix\n",
			)
		},
	}
	for index, mutate := range mutations {
		changed := validTestConfiguration()
		mutate(&changed)
		digest, err := changed.validate()
		if err != nil {
			t.Fatalf("mutation %d invalid: %v", index, err)
		}
		if digest == baseDigest {
			t.Fatalf("mutation %d retained configuration digest", index)
		}
	}
}

func TestNewCoordinatorClonesArtifactBytes(t *testing.T) {
	t.Parallel()

	config := validTestConfiguration()
	original := bytes.Clone(config.Artifacts.Kubelet.Content)
	store := &memoryJournalStore{}
	environment := newFakeUpstreams(config)
	coordinator, err := NewCoordinator(
		config,
		store,
		completeFakeDependencies(environment, &fakePreparedPublisher{}),
	)
	if err != nil {
		t.Fatal(err)
	}
	config.Artifacts.Kubelet.Content[0] ^= 0xff
	if !bytes.Equal(coordinator.config.Artifacts.Kubelet.Content, original) {
		t.Fatal("caller mutation changed coordinator configuration")
	}
}

func TestPrivateCanaryIsNotIncludedInConfigurationDigest(t *testing.T) {
	t.Parallel()

	config := validTestConfiguration()
	canary := "PRIVATE-CANARY-DO-NOT-PERSIST"
	config.Authority.KubernetesTopology = testArtifact(
		ArtifactTopologyContract,
		"decision-006-r1",
		"authorized topology "+canary+"\n",
	)
	digest, err := config.validate()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(digest, canary) {
		t.Fatal("configuration digest exposed artifact contents")
	}
	decoded, err := hex.DecodeString(digest)
	if err != nil || len(decoded) != sha256.Size {
		t.Fatalf("configuration digest = %q, want SHA-256", digest)
	}
}

type memoryJournalStore struct {
	journal Journal
}

func (s *memoryJournalStore) Load() (Journal, error) {
	return cloneJournal(s.journal), nil
}

func (s *memoryJournalStore) Save(expected uint64, next Journal) error {
	if s.journal.Revision != expected {
		return ErrJournalConflict
	}
	s.journal = cloneJournal(next)
	return nil
}
