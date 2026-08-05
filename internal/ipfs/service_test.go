// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package ipfs

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type serviceLifecycleNode struct {
	FullKuboNode
	readyErr error
	done     chan error
}

func (n *serviceLifecycleNode) Ready(context.Context) error {
	return n.readyErr
}

func (n *serviceLifecycleNode) Done() <-chan error {
	return n.done
}

type serviceNodeWithoutLifecycle struct {
	FullKuboNode
}

func TestServicePublishesSemanticReadinessAndOwnsSingleWriter(
	t *testing.T,
) {
	t.Parallel()
	config := testConfig(t)
	signer := newTestSigner(t)
	node := newFakeKuboNode(config, signer)
	service, err := StartService(
		context.Background(),
		config,
		signer,
		node,
		&fakeClock{
			now: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC),
		},
	)
	if err != nil {
		t.Fatalf("start IPFS service: %v", err)
	}
	defer func() {
		_ = service.Close()
	}()
	readyPath := filepath.Join(config.RuntimePath, readinessFilename)
	encoded, err := os.ReadFile(readyPath)
	if err != nil {
		t.Fatalf("read readiness: %v", err)
	}
	var readiness ReadinessRecord
	if err := json.Unmarshal(encoded, &readiness); err != nil {
		t.Fatalf("decode readiness: %v", err)
	}
	if !readiness.Ready ||
		readiness.Product != "kubo" ||
		readiness.RepositoryPath != config.RepositoryPath ||
		readiness.IPNSName != signer.Name() ||
		readiness.ULA != signer.ULA().String() {
		t.Fatalf("readiness = %+v", readiness)
	}

	secondNode := newFakeKuboNode(config, signer)
	_, err = StartService(
		context.Background(),
		config,
		signer,
		secondNode,
		nil,
	)
	if !errors.Is(err, ErrServiceAlreadyRunning) {
		t.Fatalf("second service error = %v, want lease denial", err)
	}
	if !secondNode.closed {
		t.Fatal("rejected second Kubo node was not closed")
	}
}

func TestServiceRunCancellationRemovesOwnedReadiness(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	signer := newTestSigner(t)
	node := newFakeKuboNode(config, signer)
	ctx, cancel := context.WithCancel(context.Background())
	service, err := StartService(ctx, config, signer, node, nil)
	if err != nil {
		t.Fatalf("start service: %v", err)
	}
	result := make(chan error, 1)
	go func() {
		result <- service.Run(ctx)
	}()
	cancel()
	select {
	case err := <-result:
		if err != nil && !strings.Contains(err.Error(), "closed network connection") {
			t.Fatalf("run after cancellation: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("service did not stop after cancellation")
	}
	if _, err := os.Stat(
		filepath.Join(config.RuntimePath, readinessFilename),
	); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("readiness remains after shutdown: %v", err)
	}
	if !node.closed {
		t.Fatal("full Kubo node was not closed")
	}
}

func TestServiceRejectsMissingOrUnreadyKuboLifecycle(t *testing.T) {
	t.Parallel()
	t.Run("missing lifecycle", func(t *testing.T) {
		t.Parallel()
		config := testConfig(t)
		signer := newTestSigner(t)
		base := newFakeKuboNode(config, signer)
		node := &serviceNodeWithoutLifecycle{FullKuboNode: base}
		if _, err := StartService(
			context.Background(),
			config,
			signer,
			node,
			nil,
		); err == nil {
			t.Fatal("node without lifecycle was accepted")
		}
		if !base.closed {
			t.Fatal("node without lifecycle was not closed")
		}
	})
	t.Run("unready lifecycle", func(t *testing.T) {
		t.Parallel()
		config := testConfig(t)
		signer := newTestSigner(t)
		base := newFakeKuboNode(config, signer)
		node := &serviceLifecycleNode{
			FullKuboNode: base,
			readyErr:     errors.New("datastore unavailable"),
			done:         make(chan error),
		}
		if _, err := StartService(
			context.Background(),
			config,
			signer,
			node,
			nil,
		); err == nil {
			t.Fatal("unready full Kubo node was accepted")
		}
		if !base.closed {
			t.Fatal("unready full Kubo node was not closed")
		}
	})
	t.Run("already stopped", func(t *testing.T) {
		t.Parallel()
		config := testConfig(t)
		signer := newTestSigner(t)
		base := newFakeKuboNode(config, signer)
		done := make(chan error, 1)
		done <- errors.New("Kubo exited")
		node := &serviceLifecycleNode{
			FullKuboNode: base,
			done:         done,
		}
		if _, err := StartService(
			context.Background(),
			config,
			signer,
			node,
			nil,
		); !errors.Is(err, ErrFullKuboStopped) {
			t.Fatalf("stopped Kubo error = %v, want stopped", err)
		}
		if !base.closed {
			t.Fatal("stopped full Kubo node was not closed")
		}
	})
}

func TestServiceKuboTerminationRemovesSemanticReadiness(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	signer := newTestSigner(t)
	base := newFakeKuboNode(config, signer)
	done := make(chan error, 1)
	node := &serviceLifecycleNode{
		FullKuboNode: base,
		done:         done,
	}
	service, err := StartService(
		context.Background(),
		config,
		signer,
		node,
		nil,
	)
	if err != nil {
		t.Fatalf("start service: %v", err)
	}
	result := make(chan error, 1)
	go func() {
		result <- service.Run(context.Background())
	}()
	done <- errors.New("Kubo process exited")
	select {
	case err := <-result:
		if !errors.Is(err, ErrFullKuboStopped) {
			t.Fatalf("Kubo termination error = %v, want stopped", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("service did not observe Kubo termination")
	}
	if _, err := os.Stat(filepath.Join(
		config.RuntimePath,
		readinessFilename,
	)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("readiness remains after Kubo termination: %v", err)
	}
	if service.Readiness().Ready {
		t.Fatal("in-memory semantic readiness remains true after termination")
	}
	if !base.closed {
		t.Fatal("terminated full Kubo node was not closed")
	}
}

func TestServiceRejectsNonKuboOrIncoherentNode(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*NodeDescriptor)
	}{
		{
			name: "Boxo replacement",
			mutate: func(value *NodeDescriptor) {
				value.Product = "boxo"
			},
		},
		{
			name: "not full Kubo",
			mutate: func(value *NodeDescriptor) {
				value.FullKubo = false
			},
		},
		{
			name: "serialized private key",
			mutate: func(value *NodeDescriptor) {
				value.PrivateKeySerialized = true
			},
		},
		{
			name: "software signer",
			mutate: func(value *NodeDescriptor) {
				value.ExternalSigner = false
			},
		},
		{
			name: "no pre-signed injection",
			mutate: func(value *NodeDescriptor) {
				value.PreSignedRecordInjection = false
			},
		},
		{
			name: "wrong repository",
			mutate: func(value *NodeDescriptor) {
				value.RepositoryPath += "-other"
			},
		},
		{
			name: "inconsistent identity",
			mutate: func(value *NodeDescriptor) {
				value.IPNSName = ""
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config := testConfig(t)
			signer := newTestSigner(t)
			node := newFakeKuboNode(config, signer)
			test.mutate(&node.descriptor)
			if _, err := StartService(
				context.Background(),
				config,
				signer,
				node,
				nil,
			); err == nil {
				t.Fatal("invalid product node was accepted")
			}
			if !node.closed {
				t.Fatal("rejected product node was not closed")
			}
			if _, err := os.Stat(filepath.Join(
				config.RuntimePath,
				readinessFilename,
			)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("invalid node published readiness: %v", err)
			}
		})
	}
}
