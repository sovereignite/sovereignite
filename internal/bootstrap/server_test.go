// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package bootstrap

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"

	pb "github.com/sovereignite/sovereignite/pkg/api/proto/sovereignite/v1"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestServerExposesCommittedBootstrapOperations(t *testing.T) {
	t.Parallel()

	serverType := reflect.TypeFor[*Server]()
	exportedMethods := make([]string, 0, serverType.NumMethod())
	for index := range serverType.NumMethod() {
		method := serverType.Method(index)
		exportedMethods = append(exportedMethods, method.Name)
	}
	want := []string{"GetStatus", "RegisterGrpcServer", "StartBootstrap"}
	if !reflect.DeepEqual(exportedMethods, want) {
		t.Fatalf("exported Server methods = %#v, want %#v", exportedMethods, want)
	}
}

func TestServerDelegatesStatusAndParameterlessStart(t *testing.T) {
	t.Parallel()

	config := validTestConfiguration()
	store, err := NewFileJournalStore(
		filepath.Join(secureTempDir(t), "journal.json"),
	)
	if err != nil {
		t.Fatal(err)
	}
	environment := newFakeUpstreams(config)
	coordinator := newTestCoordinator(
		t,
		config,
		store,
		environment,
		&fakePreparedPublisher{},
		coordinatorHooks{},
	)
	server, err := NewServer(coordinator)
	if err != nil {
		t.Fatal(err)
	}
	status, err := server.GetStatus(context.Background(), &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	if status.State != pb.BootstrapState_BOOTSTRAP_STATE_NOT_STARTED {
		t.Fatalf("initial status = %#v", status)
	}
	if _, err := server.StartBootstrap(
		context.Background(),
		&pb.StartBootstrapRequest{},
	); err != nil {
		t.Fatal(err)
	}
	status, err = server.GetStatus(context.Background(), &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	if status.State != pb.BootstrapState_BOOTSTRAP_STATE_COMPLETE {
		t.Fatalf("final status = %#v", status)
	}
}

func TestServerRejectsMissingCoordinator(t *testing.T) {
	t.Parallel()

	if _, err := NewServer(nil); err == nil {
		t.Fatal("NewServer(nil) succeeded")
	}
	var server *Server
	if _, err := server.GetStatus(context.Background(), &emptypb.Empty{}); err == nil {
		t.Fatal("nil Server.GetStatus() succeeded")
	}
	if _, err := server.StartBootstrap(
		context.Background(),
		&pb.StartBootstrapRequest{},
	); err == nil {
		t.Fatal("nil Server.StartBootstrap() succeeded")
	}
}
