// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package keyvalidation

import (
	"context"
	"testing"

	pb "github.com/sovereignite/sovereignite/pkg/api/proto/sovereignite/v1"
)

func TestValidateKey_FailClosed(t *testing.T) {
	svc := NewService()
	resp, err := svc.ValidateKey(context.Background(), &pb.ValidateKeyRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Valid {
		t.Fatal("expected Valid=false in fail-closed mode")
	}
	if resp.Identity != nil {
		t.Fatal("expected nil identity in fail-closed mode")
	}
}

func TestIssueJWT_FailClosed(t *testing.T) {
	svc := NewService()
	resp, err := svc.IssueJWT(context.Background(), &pb.IssueJWTRequest{})
	if err == nil {
		t.Fatalf("expected error, got response: %+v", resp)
	}
}

func TestValidateKey_NilRequest(t *testing.T) {
	svc := NewService()
	resp, err := svc.ValidateKey(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Valid {
		t.Fatal("expected Valid=false for nil request")
	}
}

func TestIssueJWT_NilRequest(t *testing.T) {
	svc := NewService()
	resp, err := svc.IssueJWT(context.Background(), nil)
	if err == nil {
		t.Fatalf("expected error, got response: %+v", resp)
	}
}
