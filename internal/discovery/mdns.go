// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/grandcat/zeroconf"
)

const (
	// MDNSServiceType is the fixed DNS-SD service type required by v5.
	MDNSServiceType = "_sovereignite._tcp"
	// MDNSDomain confines discovery to multicast DNS on the local link.
	MDNSDomain = "local."
)

type zeroconfServer interface {
	Shutdown()
}

type zeroconfRegisterFunc func(
	instance string,
	service string,
	domain string,
	port int,
	text []string,
	ifaces []net.Interface,
) (zeroconfServer, error)

// ZeroconfBroadcaster publishes Sovereignite DNS-SD records using mDNS.
type ZeroconfBroadcaster struct {
	register       zeroconfRegisterFunc
	cleanupTimeout time.Duration
}

// NewZeroconfBroadcaster returns the production mDNS broadcaster.
func NewZeroconfBroadcaster() *ZeroconfBroadcaster {
	return &ZeroconfBroadcaster{
		register: func(
			instance string,
			service string,
			domain string,
			port int,
			text []string,
			ifaces []net.Interface,
		) (zeroconfServer, error) {
			return zeroconf.Register(instance, service, domain, port, text, ifaces)
		},
		cleanupTimeout: defaultCleanupTimeout,
	}
}

// Start validates and publishes the fixed service type with only the planned
// TXT strings. The resulting DNS-SD records are usable by Bonjour clients
// without adding Apple-private or project-specific compatibility fields.
func (b *ZeroconfBroadcaster) Start(
	ctx context.Context,
	advertisement MDNSAdvertisement,
) (Registration, error) {
	if ctx == nil {
		return nil, errors.New("mDNS start context is required")
	}
	if b == nil || b.register == nil {
		return nil, errors.New("zeroconf registrar is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if advertisement.Port < 1 || advertisement.Port > 65535 {
		return nil, errors.New("mDNS service port must be between 1 and 65535")
	}

	record, err := DecodeRecord(advertisement.TXT)
	if err != nil {
		return nil, fmt.Errorf("validate mDNS TXT data: %w", err)
	}
	canonicalTXT, err := record.Encode()
	if err != nil {
		return nil, fmt.Errorf("encode mDNS TXT data: %w", err)
	}
	if !slices.Equal(advertisement.TXT, canonicalTXT) {
		return nil, errors.New("mDNS TXT data is not in canonical order")
	}
	if advertisement.Instance != record.DeviceID {
		return nil, errors.New("mDNS instance must equal the advertised device ID")
	}

	server, err := b.register(
		advertisement.Instance,
		MDNSServiceType,
		MDNSDomain,
		advertisement.Port,
		slices.Clone(advertisement.TXT),
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("register mDNS service: %w", err)
	}
	if server == nil {
		return nil, errors.New("register mDNS service: registrar returned no server")
	}
	registration := &zeroconfRegistration{
		server: server,
		done:   make(chan struct{}),
	}
	if err := ctx.Err(); err != nil {
		cleanupCtx, cancel := cleanupContext(b.cleanupTimeout)
		cleanupErr := registration.Stop(cleanupCtx)
		cancel()
		return nil, errors.Join(
			err,
			wrapError("stop canceled mDNS advertisement", cleanupErr),
		)
	}
	return registration, nil
}

type zeroconfRegistration struct {
	server zeroconfServer
	once   sync.Once
	done   chan struct{}
}

func (r *zeroconfRegistration) Stop(ctx context.Context) error {
	if ctx == nil {
		return errors.New("mDNS stop context is required")
	}
	r.once.Do(func() {
		go func() {
			r.server.Shutdown()
			close(r.done)
		}()
	})
	select {
	case <-r.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
