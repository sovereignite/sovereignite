// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

// Package network manages DHCP, static, and hotspot network state and
// certificate-authenticated WiFi configuration. The device is its own CA
// (D-009 resolved); WPA2/3-Enterprise EAP-TLS uses the device CA for WiFi
// client authentication. No open or password-based WiFi is permitted.
package network

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"path/filepath"
	"time"
)

var (
	// ErrInvalidNetworkTransition is returned when a state machine transition
	// is not in the explicit allowlist.
	ErrInvalidNetworkTransition = errors.New("invalid network state transition")
	// ErrUnsupportedSecurityMode is returned when a WiFi security mode outside
	// the WPA2/WPA3-Enterprise EAP-TLS allowlist is requested.
	ErrUnsupportedSecurityMode = errors.New("unsupported WiFi security mode")
)

const (
	// NetworkVersion is the sole network configuration schema version.
	NetworkVersion = 1

	// DefaultHostapdPath is the conventional hostapd binary location.
	DefaultHostapdPath = "/usr/sbin/hostapd"
	// DefaultWpaSupplicantPath is the conventional wpa_supplicant binary location.
	DefaultWpaSupplicantPath = "/usr/sbin/wpa_supplicant"
	// DefaultHostapdConfDir is the conventional hostapd configuration directory.
	DefaultHostapdConfDir = "/etc/hostapd"
	// DefaultWpaSupplicantConfDir is the conventional wpa_supplicant configuration directory.
	DefaultWpaSupplicantConfDir = "/etc/wpa_supplicant"
	// DefaultCAKeyStoreDir is the conventional device CA key/cert store directory.
	DefaultCAKeyStoreDir = "/var/lib/sovereignite/ca"

	// MaximumSSIDLength is the IEEE 802.11 maximum SSID length.
	MaximumSSIDLength = 32
	// MinimumSSIDLength is the minimum meaningful SSID length.
	MinimumSSIDLength = 1
	// MinimumChannel is the minimum valid 2.4 GHz WiFi channel.
	MinimumChannel = 1
	// MaximumChannel is the maximum valid 2.4 GHz WiFi channel.
	MaximumChannel = 14
	// MaximumCertPathLength is the maximum filesystem path length for certificate references.
	MaximumCertPathLength = 4096
)

// NetworkState is the deterministic network lifecycle state machine.
type NetworkState string

const (
	// StateBoot is the initial state before any network operation.
	StateBoot NetworkState = "boot"
	// StateDHCPDiscovery means the DHCP client is probing for a lease.
	StateDHCPDiscovery NetworkState = "dhcp_discovery"
	// StateConnected means a DHCP lease is active and the network is up.
	StateConnected NetworkState = "connected"
	// StateDHCPFailed means DHCP failed and the device falls back to static config.
	StateDHCPFailed NetworkState = "dhcp_failed"
	// StateStatic means static IP configuration is applied.
	StateStatic NetworkState = "static"
	// StateHotspotMode means the device acts as a WiFi AP for initial adoption.
	StateHotspotMode NetworkState = "hotspot_mode"
)

// ValidNetworkTransitions defines every permitted state transition. Any
// unlisted transition is rejected.
var ValidNetworkTransitions = map[NetworkState][]NetworkState{
	StateBoot:          {StateDHCPDiscovery},
	StateDHCPDiscovery: {StateConnected, StateDHCPFailed},
	StateDHCPFailed:    {StateStatic},
	StateStatic:        {StateHotspotMode},
	StateConnected:     {},
	StateHotspotMode:   {},
}

// ValidateTransition checks that a proposed state change is explicitly
// permitted. It rejects self-transitions and unknown source states.
func ValidateTransition(from, to NetworkState) error {
	if from == to {
		return fmt.Errorf(
			"%w: self-transition from %q",
			ErrInvalidNetworkTransition,
			from,
		)
	}
	targets, exists := ValidNetworkTransitions[from]
	if !exists {
		return fmt.Errorf(
			"%w: unknown source state %q",
			ErrInvalidNetworkTransition,
			from,
		)
	}
	for _, target := range targets {
		if target == to {
			return nil
		}
	}
	return fmt.Errorf(
		"%w: %q -> %q",
		ErrInvalidNetworkTransition,
		from,
		to,
	)
}

// WiFiSecurityMode is the WiFi security protocol.
type WiFiSecurityMode string

const (
	// SecurityModeWPA2Enterprise is WPA2-Enterprise with EAP-TLS.
	SecurityModeWPA2Enterprise WiFiSecurityMode = "wpa2-enterprise"
	// SecurityModeWPA3Enterprise is WPA3-Enterprise with EAP-TLS.
	SecurityModeWPA3Enterprise WiFiSecurityMode = "wpa3-enterprise"
)

// ValidWiFiSecurityModes lists every authorized WiFi security mode. Open,
// WPA-PSK, and any password-based mode is permanently excluded.
var ValidWiFiSecurityModes = map[WiFiSecurityMode]bool{
	SecurityModeWPA2Enterprise: true,
	SecurityModeWPA3Enterprise: true,
}

// HostapdConfig is the deterministic hostapd configuration for WPA2/3-Enterprise
// EAP-TLS. The device is its own CA; only adopted devices with certificates
// signed by the device CA may connect.
type HostapdConfig struct {
	// Version is the configuration schema version; must be NetworkVersion.
	Version int `json:"version"`
	// Interface is the WiFi interface name (e.g. "wlan0").
	Interface string `json:"interface"`
	// SSID is the network name broadcast by the access point.
	SSID string `json:"ssid"`
	// SecurityMode selects WPA2 or WPA3 Enterprise.
	SecurityMode WiFiSecurityMode `json:"security_mode"`
	// Channel is the WiFi radio channel.
	Channel int `json:"channel"`
	// CountryCode is the two-letter ISO 3166-1 country code.
	CountryCode string `json:"country_code"`
	// CAMertificatePath is the absolute path to the device CA certificate (PEM).
	CAMertificatePath string `json:"ca_certificate_path"`
	// ServerCertificatePath is the absolute path to the RADIUS/EAP server certificate (PEM).
	ServerCertificatePath string `json:"server_certificate_path"`
	// ServerKeyPath is the absolute path to the RADIUS/EAP server private key (PEM).
	ServerKeyPath string `json:"server_key_path"`
	// EAPCACertificatePath is the path used by hostapd's eap_server for client
	// certificate verification. This is the same device CA certificate.
	EAPCACertificatePath string `json:"eap_ca_certificate_path"`
	// EAPServerCertPath is the EAP-TLS server certificate path.
	EAPServerCertPath string `json:"eap_server_cert_path"`
	// EAPServerKeyPath is the EAP-TLS server private key path.
	EAPServerKeyPath string `json:"eap_server_key_path"`
}

// WpaSupplicantConfig is the deterministic wpa_supplicant configuration for
// WPA2/3-Enterprise EAP-TLS client authentication against the device CA.
type WpaSupplicantConfig struct {
	// Version is the configuration schema version; must be NetworkVersion.
	Version int `json:"version"`
	// Interface is the WiFi client interface name (e.g. "wlan0").
	Interface string `json:"interface"`
	// SSID is the target network SSID to associate with.
	SSID string `json:"ssid"`
	// SecurityMode selects WPA2 or WPA3 Enterprise.
	SecurityMode WiFiSecurityMode `json:"security_mode"`
	// ClientCertificatePath is the absolute path to the WiFi client certificate (PEM).
	ClientCertificatePath string `json:"client_certificate_path"`
	// ClientKeyPath is the absolute path to the WiFi client private key (PEM).
	ClientKeyPath string `json:"client_key_path"`
	// CACertificatePath is the absolute path to the device CA certificate (PEM)
	// used to verify the server certificate.
	CACertificatePath string `json:"ca_certificate_path"`
	// Identity is the EAP-TLS identity string, typically the SPIFFE ID.
	Identity string `json:"identity"`
}

// HotspotConfig bundles the device-identity-derived values needed to generate
// hostapd and wpa_supplicant configurations. It contains no private key
// material.
type HotspotConfig struct {
	// DevicePeerID is the canonical libp2p peer ID.
	DevicePeerID string
	// TrustDomain is the SPIFFE trust domain (canonical IPNS).
	TrustDomain string
	// SSID is the WiFi network name for the hotspot.
	SSID string
	// SecurityMode is the WiFi security protocol (WPA2/WPA3 Enterprise only).
	SecurityMode WiFiSecurityMode
	// Channel is the WiFi radio channel.
	Channel int
	// CountryCode is the two-letter ISO 3166-1 country code.
	CountryCode string
	// CAMertificatePath is the absolute path to the device CA certificate (PEM).
	CAMertificatePath string
	// ServerCertificatePath is the absolute path to the RADIUS/EAP server certificate (PEM).
	ServerCertificatePath string
	// ServerKeyPath is the absolute path to the RADIUS/EAP server private key (PEM).
	ServerKeyPath string
	// CAKeyStoreDir is the directory containing the device CA key material.
	CAKeyStoreDir string
}

// Validate checks every HotspotConfig field for bound compliance and rejects
// any value that would widen the WiFi security boundary.
func (c HotspotConfig) Validate() error {
	if c.DevicePeerID == "" {
		return errors.New("device peer ID is required")
	}
	if c.TrustDomain == "" {
		return errors.New("trust domain is required")
	}
	if len(c.SSID) < MinimumSSIDLength || len(c.SSID) > MaximumSSIDLength {
		return fmt.Errorf(
			"SSID length %d is outside [%d, %d]",
			len(c.SSID),
			MinimumSSIDLength,
			MaximumSSIDLength,
		)
	}
	if !ValidWiFiSecurityModes[c.SecurityMode] {
		return fmt.Errorf(
			"%w: %q",
			ErrUnsupportedSecurityMode,
			c.SecurityMode,
		)
	}
	if c.Channel < MinimumChannel || c.Channel > MaximumChannel {
		return fmt.Errorf(
			"channel %d is outside [%d, %d]",
			c.Channel,
			MinimumChannel,
			MaximumChannel,
		)
	}
	if c.CountryCode == "" || len(c.CountryCode) != 2 {
		return errors.New("country code must be a two-letter ISO 3166-1 code")
	}
	if c.CAMertificatePath == "" {
		return errors.New("CA certificate path is required")
	}
	if len(c.CAMertificatePath) > MaximumCertPathLength {
		return fmt.Errorf(
			"CA certificate path exceeds %d bytes",
			MaximumCertPathLength,
		)
	}
	if err := validateAbsoluteCertPath(c.CAMertificatePath, "CA certificate"); err != nil {
		return err
	}
	if c.ServerCertificatePath == "" {
		return errors.New("server certificate path is required")
	}
	if err := validateAbsoluteCertPath(c.ServerCertificatePath, "server certificate"); err != nil {
		return err
	}
	if c.ServerKeyPath == "" {
		return errors.New("server key path is required")
	}
	if err := validateAbsoluteCertPath(c.ServerKeyPath, "server key"); err != nil {
		return err
	}
	if c.CAKeyStoreDir == "" {
		return errors.New("CA key store directory is required")
	}
	if !filepath.IsAbs(c.CAKeyStoreDir) {
		return errors.New("CA key store directory must be an absolute path")
	}
	return nil
}

func validateAbsoluteCertPath(rawPath, description string) error {
	path := filepath.Clean(rawPath)
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%s path must be absolute", description)
	}
	if len(path) > MaximumCertPathLength {
		return fmt.Errorf(
			"%s path exceeds %d bytes",
			description,
			MaximumCertPathLength,
		)
	}
	return nil
}

// Generator produces deterministic hostapd and wpa_supplicant configurations
// and WiFi client certificate templates from a validated HotspotConfig.
type Generator struct {
	config HotspotConfig
}

// NewGenerator validates the hotspot configuration before any rendering.
func NewGenerator(config HotspotConfig) (*Generator, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("hotspot generator config: %w", err)
	}
	return &Generator{config: config}, nil
}

// GenerateHostapdConfig renders the deterministic hostapd configuration for
// WPA2/3-Enterprise EAP-TLS. The configuration references only the device CA
// certificate and server key material; no passwords or PSKs are used.
func (g *Generator) GenerateHostapdConfig() HostapdConfig {
	conf := HostapdConfig{
		Version:               NetworkVersion,
		Interface:             "wlan0",
		SSID:                  g.config.SSID,
		SecurityMode:          g.config.SecurityMode,
		Channel:               g.config.Channel,
		CountryCode:           g.config.CountryCode,
		CAMertificatePath:     g.config.CAMertificatePath,
		ServerCertificatePath: g.config.ServerCertificatePath,
		ServerKeyPath:         g.config.ServerKeyPath,
	}
	conf.EAPCACertificatePath = g.config.CAMertificatePath
	conf.EAPServerCertPath = g.config.ServerCertificatePath
	conf.EAPServerKeyPath = g.config.ServerKeyPath
	return conf
}

// GenerateWpaSupplicantConfig renders the deterministic wpa_supplicant
// configuration for EAP-TLS client authentication. The client certificate and
// key paths are placeholders that must be filled after certificate issuance.
func (g *Generator) GenerateWpaSupplicantConfig(
	clientCertificatePath string,
	clientKeyPath string,
	identity string,
) (WpaSupplicantConfig, error) {
	if clientCertificatePath == "" {
		return WpaSupplicantConfig{}, errors.New(
			"client certificate path is required",
		)
	}
	if err := validateAbsoluteCertPath(
		clientCertificatePath,
		"client certificate",
	); err != nil {
		return WpaSupplicantConfig{}, err
	}
	if clientKeyPath == "" {
		return WpaSupplicantConfig{}, errors.New(
			"client key path is required",
		)
	}
	if err := validateAbsoluteCertPath(clientKeyPath, "client key"); err != nil {
		return WpaSupplicantConfig{}, err
	}
	if identity == "" {
		return WpaSupplicantConfig{}, errors.New("EAP-TLS identity is required")
	}
	return WpaSupplicantConfig{
		Version:               NetworkVersion,
		Interface:             "wlan0",
		SSID:                  g.config.SSID,
		SecurityMode:          g.config.SecurityMode,
		ClientCertificatePath: clientCertificatePath,
		ClientKeyPath:         clientKeyPath,
		CACertificatePath:     g.config.CAMertificatePath,
		Identity:              identity,
	}, nil
}

// WiFiClientCertificateTemplate returns an x509.Certificate template for a
// WiFi client certificate signed by the device CA. The template is authorized
// only for EAP-TLS client authentication and must not be used for any other
// purpose. The caller provides notBefore/notAfter bounds; the template itself
// contains no private key material.
func (g *Generator) WiFiClientCertificateTemplate(
	relationshipID string,
	spiffeID string,
	serialNumber *big.Int,
	notBefore time.Time,
	notAfter time.Time,
) (*x509.Certificate, error) {
	if relationshipID == "" {
		return nil, errors.New("relationship ID is required")
	}
	if spiffeID == "" {
		return nil, errors.New("SPIFFE ID is required")
	}
	if serialNumber == nil || serialNumber.Sign() <= 0 {
		return nil, errors.New("serial number must be positive")
	}
	if notBefore.IsZero() {
		return nil, errors.New("notBefore is required")
	}
	if notAfter.IsZero() || !notAfter.After(notBefore) {
		return nil, errors.New("notAfter must be after notBefore")
	}

	spiffeURI, err := url.Parse(spiffeID)
	if err != nil {
		return nil, fmt.Errorf("parse SPIFFE ID: %w", err)
	}
	if spiffeURI.Scheme != "spiffe" || spiffeURI.Host == "" || spiffeURI.Path == "" {
		return nil, errors.New("SPIFFE ID must have spiffe scheme, host, and path")
	}
	return &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   spiffeID,
			Organization: []string{"Sovereignite"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{spiffeURI},
	}, nil
}

// HostapdConfigPath returns the conventional hostapd configuration file path.
func (g *Generator) HostapdConfigPath() string {
	return filepath.Join(DefaultHostapdConfDir, "hostapd.conf")
}

// WpaSupplicantConfigPath returns the conventional wpa_supplicant configuration
// file path.
func (g *Generator) WpaSupplicantConfigPath() string {
	return filepath.Join(DefaultWpaSupplicantConfDir, "wpa_supplicant.conf")
}

// CAMertificatePath returns the device CA certificate path from the
// configuration.
func (g *Generator) CAMertificatePath() string {
	return g.config.CAMertificatePath
}

// CAKeyStoreDir returns the device CA key store directory from the
// configuration.
func (g *Generator) CAKeyStoreDir() string {
	return g.config.CAKeyStoreDir
}
