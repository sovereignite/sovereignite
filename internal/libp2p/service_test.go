// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package libp2p

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func isListenerClosedError(err error) bool {
	return strings.Contains(err.Error(), "closed network connection")
}

func TestStartRequiresRealHostBeforeAnyMutation(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	hostnamectl := &fakeHostnamectl{}
	if _, err := Start(
		context.Background(),
		config,
		newFakeTPMKey(t, firstPersistentHandle+49),
		nil,
		hostnamectl,
	); !errors.Is(err, ErrHostUnavailable) {
		t.Fatalf("Start error = %v, want real-host unavailable", err)
	}
	if calls := hostnamectl.Calls(); len(calls) != 0 {
		t.Fatalf("hostnamectl called %d times without a real host", len(calls))
	}
	for _, path := range []string{config.StateRoot, config.RuntimeRoot} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("metadata path %q exists without a real host: %v", path, err)
		}
	}
}

func TestStartRejectsHostBoundToDifferentIdentityBeforeMutation(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	runningHost := &fakeRunningHost{id: "different-peer"}
	launcher := hostLauncherFunc(func(
		_ context.Context,
		_ *Identity,
	) (RunningHost, error) {
		return runningHost, nil
	})
	hostnameSetter := &fakeHostnamectl{}
	if _, err := Start(
		context.Background(),
		config,
		newFakeTPMKey(t, firstPersistentHandle+59),
		launcher,
		hostnameSetter,
	); !errors.Is(err, ErrHostUnavailable) {
		t.Fatalf("Start error = %v, want host unavailable", err)
	}
	if calls := runningHost.CloseCalls(); calls != 1 {
		t.Fatalf("mismatched host close count = %d, want 1", calls)
	}
	if calls := hostnameSetter.Calls(); len(calls) != 0 {
		t.Fatalf("hostname changed %d times for mismatched host", len(calls))
	}
	for _, path := range []string{config.StateRoot, config.RuntimeRoot} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("metadata path %q exists for mismatched host: %v", path, err)
		}
	}
}

func TestServicePublishesLoopbackReadinessUntilCancellation(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	key := newFakeTPMKey(t, firstPersistentHandle+50)
	ctx, cancel := context.WithCancel(context.Background())
	service, err := Start(
		ctx,
		config,
		key,
		&fakeHostLauncher{},
		&fakeHostnamectl{},
	)
	if err != nil {
		cancel()
		t.Fatalf("start identity service: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		_ = service.Close()
	})

	recordContent, err := os.ReadFile(config.endpointPath())
	if err != nil {
		t.Fatalf("read endpoint record: %v", err)
	}
	var persisted EndpointRecord
	if err := json.Unmarshal(recordContent, &persisted); err != nil {
		t.Fatalf("decode endpoint record: %v", err)
	}
	if persisted != service.Endpoint() {
		t.Fatalf("persisted endpoint = %#v, want %#v", persisted, service.Endpoint())
	}
	if persisted.Version != endpointRecordVersion {
		t.Fatalf("endpoint version = %d, want %d", persisted.Version, endpointRecordVersion)
	}
	if persisted.Service != "identity" {
		t.Fatalf("endpoint service = %q, want identity", persisted.Service)
	}
	if !isCanonicalUUID(persisted.BootID) {
		t.Fatalf("endpoint boot ID = %q, want canonical UUID", persisted.BootID)
	}
	if len(persisted.InstanceNonce) != 32 {
		t.Fatalf(
			"endpoint instance nonce length = %d, want 32",
			len(persisted.InstanceNonce),
		)
	}
	if persisted.PID != os.Getpid() {
		t.Fatalf("endpoint PID = %d, want %d", persisted.PID, os.Getpid())
	}
	if persisted.Network != "tcp4" {
		t.Fatalf("endpoint network = %q, want tcp4", persisted.Network)
	}
	if persisted.ExpectedIdentity != service.Identity().Name {
		t.Fatalf(
			"endpoint identity = %q, want %q",
			persisted.ExpectedIdentity,
			service.Identity().Name,
		)
	}
	addressValue, err := netip.ParseAddr(persisted.Address)
	if err != nil {
		t.Fatalf("parse endpoint address: %v", err)
	}
	address := netip.AddrPortFrom(addressValue, persisted.Port)
	if address.Addr() != netip.MustParseAddr("127.0.0.1") ||
		address.Port() < minimumHighPort {
		t.Fatalf("endpoint address = %v, want high IPv4 loopback port", address)
	}
	info, err := os.Stat(config.endpointPath())
	if err != nil {
		t.Fatalf("stat endpoint record: %v", err)
	}
	if permissions := info.Mode().Perm(); permissions != 0o600 {
		t.Fatalf("endpoint permissions = %o, want 600", permissions)
	}
	runtimeInfo, err := os.Stat(config.RuntimeRoot)
	if err != nil {
		t.Fatalf("stat runtime root: %v", err)
	}
	if permissions := runtimeInfo.Mode().Perm(); permissions != 0o700 {
		t.Fatalf("runtime root permissions = %o, want 700", permissions)
	}
	lockInfo, err := os.Stat(config.runtimeLockPath())
	if err != nil {
		t.Fatalf("stat runtime lock: %v", err)
	}
	if permissions := lockInfo.Mode().Perm(); permissions != 0o600 {
		t.Fatalf("runtime lock permissions = %o, want 600", permissions)
	}

	runResult := make(chan error, 1)
	go func() {
		runResult <- service.Run(ctx)
	}()
	select {
	case err := <-runResult:
		t.Fatalf("service stopped before cancellation: %v", err)
	case <-time.After(25 * time.Millisecond):
	}

	connection, err := net.DialTimeout("tcp4", address.String(), time.Second)
	if err != nil {
		t.Fatalf("dial readiness endpoint: %v", err)
	}
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		_ = connection.Close()
		t.Fatalf("set readiness read deadline: %v", err)
	}
	buffer := make([]byte, 1)
	if _, err := connection.Read(buffer); !errors.Is(err, io.EOF) {
		_ = connection.Close()
		t.Fatalf("readiness connection read error = %v, want EOF", err)
	}
	if err := connection.Close(); err != nil {
		t.Fatalf("close readiness connection: %v", err)
	}

	cancel()
	select {
	case err := <-runResult:
		if err != nil && !isListenerClosedError(err) {
			t.Fatalf("service run after cancellation: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("service did not stop after cancellation")
	}
	if _, err := os.Stat(config.endpointPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("endpoint record still exists after shutdown: %v", err)
	}
	if _, err := os.Stat(config.statePath()); err != nil {
		t.Fatalf("stable identity state missing after shutdown: %v", err)
	}
}

func TestConcurrentStartHasExactlyOneLeaseWinner(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	ready := make(chan struct{}, 2)
	release := make(chan struct{})
	launcher := hostLauncherFunc(func(
		_ context.Context,
		identity *Identity,
	) (RunningHost, error) {
		ready <- struct{}{}
		<-release
		return &fakeRunningHost{id: identity.PeerID}, nil
	})
	keys := []*fakeTPMKey{
		newFakeTPMKey(t, firstPersistentHandle+56),
		newFakeTPMKey(t, firstPersistentHandle+56),
	}
	runners := []*fakeHostnamectl{{}, {}}
	type startResult struct {
		service *Service
		err     error
	}
	results := make(chan startResult, 2)
	var start sync.WaitGroup
	start.Add(1)
	for index := range keys {
		index := index
		go func() {
			start.Wait()
			service, err := Start(
				context.Background(),
				config,
				keys[index],
				launcher,
				runners[index],
			)
			results <- startResult{service: service, err: err}
		}()
	}
	start.Done()
	for count := 0; count < 2; count++ {
		select {
		case <-ready:
		case <-time.After(2 * time.Second):
			t.Fatal("concurrent Starts did not reach the host barrier")
		}
	}
	close(release)

	var winner *Service
	successes := 0
	alreadyRunning := 0
	for count := 0; count < 2; count++ {
		result := <-results
		switch {
		case result.err == nil:
			successes++
			winner = result.service
		case errors.Is(result.err, ErrServiceAlreadyRunning):
			alreadyRunning++
		default:
			t.Fatalf("unexpected concurrent Start error: %v", result.err)
		}
	}
	if successes != 1 || alreadyRunning != 1 {
		if winner != nil {
			_ = winner.Close()
		}
		t.Fatalf(
			"concurrent Starts = %d successes/%d lease failures, want 1/1",
			successes,
			alreadyRunning,
		)
	}
	if winner == nil {
		t.Fatal("concurrent Start did not return its lease winner")
	}
	endpointContent, err := os.ReadFile(config.endpointPath())
	if err != nil {
		_ = winner.Close()
		t.Fatalf("read winning endpoint: %v", err)
	}
	var winningEndpoint EndpointRecord
	if err := json.Unmarshal(endpointContent, &winningEndpoint); err != nil {
		_ = winner.Close()
		t.Fatalf("decode winning endpoint: %v", err)
	}
	if winningEndpoint != winner.Endpoint() {
		_ = winner.Close()
		t.Fatalf(
			"published endpoint = %#v, want winner %#v",
			winningEndpoint,
			winner.Endpoint(),
		)
	}
	if err := winner.Close(); err != nil {
		t.Fatalf("close concurrent Start winner: %v", err)
	}
	hostnameCalls := len(runners[0].Calls()) + len(runners[1].Calls())
	if hostnameCalls != 1 {
		t.Fatalf("hostnamectl total call count = %d, want 1", hostnameCalls)
	}
}

func TestStartEnforcesSingleRuntimeOwner(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	key := newFakeTPMKey(t, firstPersistentHandle+52)
	first, err := Start(
		context.Background(),
		config,
		key,
		&fakeHostLauncher{},
		&fakeHostnamectl{},
	)
	if err != nil {
		t.Fatalf("start first identity service: %v", err)
	}
	firstNonce := first.Endpoint().InstanceNonce
	secondHostnamectl := &fakeHostnamectl{}
	secondKey := newFakeTPMKey(t, firstPersistentHandle+52)
	if _, err := Start(
		context.Background(),
		config,
		secondKey,
		&fakeHostLauncher{},
		secondHostnamectl,
	); !errors.Is(err, ErrServiceAlreadyRunning) {
		_ = first.Close()
		t.Fatalf("second Start error = %v, want already running", err)
	}
	if calls := secondHostnamectl.Calls(); len(calls) != 0 {
		_ = first.Close()
		t.Fatalf("second Start changed hostname %d times", len(calls))
	}
	endpointContent, err := os.ReadFile(config.endpointPath())
	if err != nil {
		_ = first.Close()
		t.Fatalf("read endpoint after second Start: %v", err)
	}
	var endpointAfterSecond EndpointRecord
	if err := json.Unmarshal(endpointContent, &endpointAfterSecond); err != nil {
		_ = first.Close()
		t.Fatalf("decode endpoint after second Start: %v", err)
	}
	if endpointAfterSecond.InstanceNonce != firstNonce {
		_ = first.Close()
		t.Fatal("second Start replaced the active endpoint record")
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close first identity service: %v", err)
	}

	third, err := Start(
		context.Background(),
		config,
		key,
		&fakeHostLauncher{},
		&fakeHostnamectl{},
	)
	if err != nil {
		t.Fatalf("restart identity service after releasing lease: %v", err)
	}
	defer func() {
		_ = third.Close()
	}()
	if third.Endpoint().InstanceNonce == firstNonce {
		t.Fatal("service restart reused its process instance nonce")
	}
}

func TestStartRejectsPermissiveExistingRuntimeLockUnchanged(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	if err := os.MkdirAll(config.RuntimeRoot, 0o700); err != nil {
		t.Fatalf("create runtime root: %v", err)
	}
	if err := os.WriteFile(config.runtimeLockPath(), nil, 0o600); err != nil {
		t.Fatalf("create runtime lock: %v", err)
	}
	if err := os.Chmod(config.runtimeLockPath(), 0o644); err != nil {
		t.Fatalf("make runtime lock permissive: %v", err)
	}
	hostnamectl := &fakeHostnamectl{}
	if _, err := Start(
		context.Background(),
		config,
		newFakeTPMKey(t, firstPersistentHandle+57),
		&fakeHostLauncher{},
		hostnamectl,
	); err == nil {
		t.Fatal("permissive existing runtime lock was accepted")
	}
	info, err := os.Stat(config.runtimeLockPath())
	if err != nil {
		t.Fatalf("stat rejected runtime lock: %v", err)
	}
	if permissions := info.Mode().Perm(); permissions != 0o644 {
		t.Fatalf("runtime lock permissions changed to %o, want unchanged 644", permissions)
	}
	if _, err := os.Stat(config.statePath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("identity state created before runtime-lock rejection: %v", err)
	}
	if calls := hostnamectl.Calls(); len(calls) != 0 {
		t.Fatalf("hostnamectl called %d times for rejected runtime lock", len(calls))
	}
}

func TestCloseDoesNotDeleteForeignEndpointReplacement(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	service, err := Start(
		context.Background(),
		config,
		newFakeTPMKey(t, firstPersistentHandle+58),
		&fakeHostLauncher{},
		&fakeHostnamectl{},
	)
	if err != nil {
		t.Fatalf("start identity service: %v", err)
	}
	// Use byte-for-byte identical content so cleanup must rely on ownership of
	// the published inode, not only an attacker-copyable endpoint payload.
	foreign := append([]byte(nil), service.endpointBytes...)
	replacement := filepath.Join(config.RuntimeRoot, "foreign-endpoint.json")
	if err := os.WriteFile(replacement, foreign, 0o600); err != nil {
		_ = service.Close()
		t.Fatalf("write foreign endpoint replacement: %v", err)
	}
	if err := os.Rename(replacement, config.endpointPath()); err != nil {
		_ = service.Close()
		t.Fatalf("replace owned endpoint: %v", err)
	}
	if err := service.Close(); err != nil {
		t.Fatalf("close service after foreign endpoint replacement: %v", err)
	}
	content, err := os.ReadFile(config.endpointPath())
	if err != nil {
		t.Fatalf("foreign endpoint replacement was deleted: %v", err)
	}
	if string(content) != string(foreign) {
		t.Fatalf("foreign endpoint content = %q, want %q", content, foreign)
	}
}

func TestStartRejectsSymlinkedRuntimeRootBeforeIdentityMutation(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	base := filepath.Dir(config.RuntimeRoot)
	target := filepath.Join(base, "runtime-target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("create runtime symlink target: %v", err)
	}
	link := filepath.Join(base, "runtime-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("create runtime-root symlink: %v", err)
	}
	config.RuntimeRoot = filepath.Join(link, "identity")
	hostnamectl := &fakeHostnamectl{}
	if _, err := Start(
		context.Background(),
		config,
		newFakeTPMKey(t, firstPersistentHandle+53),
		&fakeHostLauncher{},
		hostnamectl,
	); err == nil {
		t.Fatal("symlinked runtime root was accepted")
	}
	if calls := hostnamectl.Calls(); len(calls) != 0 {
		t.Fatalf("hostnamectl called %d times for symlinked runtime root", len(calls))
	}
	if _, err := os.Stat(config.statePath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stable identity created before runtime-root rejection: %v", err)
	}
	if _, err := os.Stat(filepath.Join(target, "identity")); !errors.Is(
		err,
		os.ErrNotExist,
	) {
		t.Fatalf("write escaped through runtime-root symlink: %v", err)
	}
}

func TestStartRejectsSymlinkedRuntimeLockBeforeIdentityMutation(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	if err := os.MkdirAll(config.RuntimeRoot, 0o700); err != nil {
		t.Fatalf("create runtime root: %v", err)
	}
	target := filepath.Join(filepath.Dir(config.RuntimeRoot), "lock-target")
	original := []byte("do not lock\n")
	if err := os.WriteFile(target, original, 0o600); err != nil {
		t.Fatalf("write lock symlink target: %v", err)
	}
	if err := os.Symlink(target, config.runtimeLockPath()); err != nil {
		t.Fatalf("create runtime-lock symlink: %v", err)
	}
	hostnamectl := &fakeHostnamectl{}
	if _, err := Start(
		context.Background(),
		config,
		newFakeTPMKey(t, firstPersistentHandle+54),
		&fakeHostLauncher{},
		hostnamectl,
	); err == nil {
		t.Fatal("symlinked runtime lock was accepted")
	}
	if calls := hostnamectl.Calls(); len(calls) != 0 {
		t.Fatalf("hostnamectl called %d times for symlinked runtime lock", len(calls))
	}
	if _, err := os.Stat(config.statePath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stable identity created before runtime-lock rejection: %v", err)
	}
	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read runtime-lock symlink target: %v", err)
	}
	if string(content) != string(original) {
		t.Fatal("runtime-lock symlink target was changed")
	}
}

func TestStartRejectsPermissiveRuntimeRootWithoutChangingMode(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	if err := os.MkdirAll(config.RuntimeRoot, 0o700); err != nil {
		t.Fatalf("create runtime root: %v", err)
	}
	if err := os.Chmod(config.RuntimeRoot, 0o755); err != nil {
		t.Fatalf("make runtime root permissive: %v", err)
	}
	hostnamectl := &fakeHostnamectl{}
	if _, err := Start(
		context.Background(),
		config,
		newFakeTPMKey(t, firstPersistentHandle+55),
		&fakeHostLauncher{},
		hostnamectl,
	); err == nil {
		t.Fatal("permissive runtime root was accepted")
	}
	info, err := os.Stat(config.RuntimeRoot)
	if err != nil {
		t.Fatalf("stat rejected runtime root: %v", err)
	}
	if permissions := info.Mode().Perm(); permissions != 0o755 {
		t.Fatalf("runtime root permissions changed to %o, want unchanged 755", permissions)
	}
	if _, err := os.Stat(config.statePath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("identity state created before runtime-root rejection: %v", err)
	}
	if calls := hostnamectl.Calls(); len(calls) != 0 {
		t.Fatalf("hostnamectl called %d times for rejected runtime root", len(calls))
	}
}

func TestStartWithCanceledContextHasNoSideEffects(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	hostnamectl := &fakeHostnamectl{}
	if _, err := Start(
		ctx,
		config,
		newFakeTPMKey(t, firstPersistentHandle+51),
		&fakeHostLauncher{},
		hostnamectl,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("Start error = %v, want context canceled", err)
	}
	if calls := hostnamectl.Calls(); len(calls) != 0 {
		t.Fatalf("hostnamectl called %d times with canceled context", len(calls))
	}
	if _, err := os.Stat(config.statePath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("identity state exists after canceled Start: %v", err)
	}
	if _, err := os.Stat(config.endpointPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("endpoint exists after canceled Start: %v", err)
	}
}

func TestServiceBindsLoopbackPortZero(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	key := newFakeTPMKey(t, firstPersistentHandle+60)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	service, err := Start(
		ctx,
		config,
		key,
		&fakeHostLauncher{},
		&fakeHostnamectl{},
	)
	if err != nil {
		cancel()
		t.Fatalf("start identity service: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		_ = service.Close()
	})
	addr, err := netip.ParseAddrPort(service.Endpoint().Address + ":" +
		strconv.Itoa(int(service.Endpoint().Port)))
	if err != nil {
		t.Fatalf("parse endpoint address: %v", err)
	}
	if addr.Addr() != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf(
			"endpoint address = %v, want 127.0.0.1",
			addr.Addr(),
		)
	}
	if addr.Port() < minimumHighPort {
		t.Fatalf(
			"endpoint port = %d, want >= %d",
			addr.Port(),
			minimumHighPort,
		)
	}
}

func TestIdentitySurvivesServiceRestart(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	key := newFakeTPMKey(t, firstPersistentHandle+61)
	hostnamectl := &fakeHostnamectl{}

	ctx1, cancel1 := context.WithCancel(context.Background())
	first, err := Start(
		ctx1,
		config,
		key,
		&fakeHostLauncher{},
		hostnamectl,
	)
	if err != nil {
		cancel1()
		t.Fatalf("start first identity service: %v", err)
	}
	firstIdentity := first.Identity()
	firstName := firstIdentity.Name
	firstPeerID := firstIdentity.PeerID
	cancel1()
	if err := first.Close(); err != nil {
		t.Fatalf("close first identity service: %v", err)
	}

	second, err := Start(
		context.Background(),
		config,
		key,
		&fakeHostLauncher{},
		hostnamectl,
	)
	if err != nil {
		t.Fatalf("restart identity service: %v", err)
	}
	defer func() {
		_ = second.Close()
	}()
	if second.Identity().Name != firstName {
		t.Fatalf(
			"identity name changed after restart: first %q, second %q",
			firstName,
			second.Identity().Name,
		)
	}
	if second.Identity().PeerID != firstPeerID {
		t.Fatalf(
			"peer ID changed after restart: first %q, second %q",
			firstPeerID,
			second.Identity().PeerID,
		)
	}
	if second.Endpoint().InstanceNonce == first.Endpoint().InstanceNonce {
		t.Fatal("restart reused process instance nonce")
	}
}
