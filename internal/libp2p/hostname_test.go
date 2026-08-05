// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package libp2p

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestValidateHostnameLabel(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		value string
		valid bool
	}{
		{name: "single letter", value: "a", valid: true},
		{name: "CID-shaped", value: "k51qzi5uqu5dl-example", valid: true},
		{name: "63 bytes", value: strings.Repeat("a", 63), valid: true},
		{name: "empty", value: "", valid: false},
		{name: "too long", value: strings.Repeat("a", 64), valid: false},
		{name: "uppercase", value: "Abc", valid: false},
		{name: "leading hyphen", value: "-abc", valid: false},
		{name: "trailing hyphen", value: "abc-", valid: false},
		{name: "dot", value: "abc.example", valid: false},
		{name: "slash", value: "/ipns/abc", valid: false},
		{name: "underscore", value: "abc_def", valid: false},
		{name: "non-ASCII", value: "café", valid: false},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateHostnameLabel(test.value)
			if test.valid && err != nil {
				t.Fatalf("valid label rejected: %v", err)
			}
			if !test.valid && err == nil {
				t.Fatal("invalid label accepted")
			}
		})
	}
}

func TestSetValidatedHostnameDoesNotMutateInvalidName(t *testing.T) {
	t.Parallel()
	setter := &fakeHostnamectl{}
	if err := SetValidatedHostname(
		context.Background(),
		setter,
		"INVALID",
	); err == nil {
		t.Fatal("invalid hostname was accepted")
	}
	if calls := setter.Calls(); len(calls) != 0 {
		t.Fatalf("hostname setter called %d times for invalid hostname", len(calls))
	}
}

func TestSetValidatedHostnamePassesCanonicalName(t *testing.T) {
	t.Parallel()
	setter := &fakeHostnamectl{}
	if err := SetValidatedHostname(
		context.Background(),
		setter,
		"k51example",
	); err != nil {
		t.Fatalf("set validated hostname: %v", err)
	}
	calls := setter.Calls()
	if len(calls) != 1 {
		t.Fatalf("hostname setter call count = %d, want 1", len(calls))
	}
	if calls[0].name != "k51example" {
		t.Fatalf("hostname = %q, want k51example", calls[0].name)
	}
}

func TestSetValidatedHostnamePropagatesSetterError(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("hostname1 failed")
	setter := &fakeHostnamectl{err: sentinel}
	err := SetValidatedHostname(context.Background(), setter, "k51example")
	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want wrapped setter error", err)
	}
}

type hostnameBusCall struct {
	method string
	args   []any
}

type fakeHostnameBus struct {
	mutex      sync.Mutex
	calls      []hostnameBusCall
	callErrors map[string]error
	closeError error
	closed     bool
}

func (bus *fakeHostnameBus) Call(
	ctx context.Context,
	method string,
	args ...any,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	bus.mutex.Lock()
	defer bus.mutex.Unlock()
	bus.calls = append(bus.calls, hostnameBusCall{
		method: method,
		args:   append([]any(nil), args...),
	})
	return bus.callErrors[method]
}

func (bus *fakeHostnameBus) Close() error {
	bus.mutex.Lock()
	defer bus.mutex.Unlock()
	bus.closed = true
	return bus.closeError
}

func (bus *fakeHostnameBus) snapshot() ([]hostnameBusCall, bool) {
	bus.mutex.Lock()
	defer bus.mutex.Unlock()
	return append([]hostnameBusCall(nil), bus.calls...), bus.closed
}

func TestDBusHostnameSetterUsesOnlyFixedHostname1Methods(t *testing.T) {
	t.Parallel()
	bus := &fakeHostnameBus{}
	setter := DBusHostnameSetter{
		connect: func(ctx context.Context) (hostnameBus, error) {
			if _, ok := ctx.Deadline(); !ok {
				t.Fatal("D-Bus connection context has no deadline")
			}
			return bus, nil
		},
		timeout: time.Second,
	}
	if err := setter.SetHostname(context.Background(), "k51example"); err != nil {
		t.Fatalf("set hostname through D-Bus: %v", err)
	}
	calls, closed := bus.snapshot()
	if !closed {
		t.Fatal("system D-Bus connection was not closed")
	}
	if len(calls) != 2 {
		t.Fatalf("D-Bus call count = %d, want 2", len(calls))
	}
	expectedMethods := []string{
		setStaticHostnameMethod,
		setTransientHostnameMethod,
	}
	for index, expected := range expectedMethods {
		call := calls[index]
		if call.method != expected {
			t.Fatalf("D-Bus call %d method = %q, want %q", index, call.method, expected)
		}
		if len(call.args) != 2 ||
			call.args[0] != "k51example" ||
			call.args[1] != false {
			t.Fatalf("D-Bus call %d args = %#v, want canonical name/false", index, call.args)
		}
	}
}

func TestDBusHostnameSetterPropagatesConnectionAndMethodErrors(t *testing.T) {
	t.Parallel()
	connectError := errors.New("system bus unavailable")
	err := (DBusHostnameSetter{
		connect: func(context.Context) (hostnameBus, error) {
			return nil, connectError
		},
	}).SetHostname(context.Background(), "k51example")
	if !errors.Is(err, connectError) {
		t.Fatalf("connection error = %v, want wrapped sentinel", err)
	}
	err = (DBusHostnameSetter{
		connect: func(context.Context) (hostnameBus, error) {
			return nil, nil
		},
	}).SetHostname(context.Background(), "k51example")
	if err == nil {
		t.Fatal("nil D-Bus connection was accepted")
	}

	callError := errors.New("hostname1 denied mutation")
	bus := &fakeHostnameBus{
		callErrors: map[string]error{setStaticHostnameMethod: callError},
	}
	err = (DBusHostnameSetter{
		connect: func(context.Context) (hostnameBus, error) {
			return bus, nil
		},
	}).SetHostname(context.Background(), "k51example")
	if !errors.Is(err, callError) {
		t.Fatalf("method error = %v, want wrapped sentinel", err)
	}
	calls, closed := bus.snapshot()
	if !closed {
		t.Fatal("D-Bus connection was not closed after method failure")
	}
	if len(calls) != 1 {
		t.Fatalf("D-Bus calls after first failure = %d, want 1", len(calls))
	}

	closeError := errors.New("close system bus")
	bus = &fakeHostnameBus{closeError: closeError}
	err = (DBusHostnameSetter{
		connect: func(context.Context) (hostnameBus, error) {
			return bus, nil
		},
	}).SetHostname(context.Background(), "k51example")
	if !errors.Is(err, closeError) {
		t.Fatalf("close error = %v, want wrapped sentinel", err)
	}
}

func TestDBusHostnameSetterHonorsBoundedContext(t *testing.T) {
	t.Parallel()
	setter := DBusHostnameSetter{
		connect: func(ctx context.Context) (hostnameBus, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
		timeout: time.Millisecond,
	}
	err := setter.SetHostname(context.Background(), "k51example")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("bounded hostname error = %v, want deadline exceeded", err)
	}
}
