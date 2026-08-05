// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package main

import (
	"context"
	"testing"
	"time"
)

func TestRunRejectsExtraArguments(t *testing.T) {
	t.Parallel()

	err := run(context.Background(), []string{"status"})
	if err == nil {
		t.Fatal("run() accepted extra arguments")
	}
}

func TestRunServesUntilContextCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := run(ctx, nil)
	if err != nil {
		t.Fatalf("run() error = %v", err)
	}
}

func TestStubCoordinatorCreation(t *testing.T) {
	t.Parallel()

	coordinator, err := newStubCoordinator()
	if err != nil {
		t.Fatalf("newStubCoordinator() error = %v", err)
	}
	if coordinator == nil {
		t.Fatal("newStubCoordinator() returned nil coordinator")
	}
}
