// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package network

import (
	"crypto/x509"
	"math/big"
	"testing"
	"time"
)

func validHotspotConfig() HotspotConfig {
	return HotspotConfig{
		DevicePeerID:         "12D3KooWBhTbHvhCFPgRdgmfvGMNHxqgFMFyGRzEeMH2bMqFKFEi",
		TrustDomain:          "bafybeigdyrzhk6dyp3wklsazmcei4rb4l5q3ci3dgbp2g5xu5e7xq4abcde",
		SSID:                 "Sovereignite",
		SecurityMode:         SecurityModeWPA2Enterprise,
		Channel:              6,
		CountryCode:          "US",
		CAMertificatePath:    "/var/lib/sovereignite/ca/ca.pem",
		ServerCertificatePath: "/var/lib/sovereignite/ca/server.pem",
		ServerKeyPath:        "/var/lib/sovereignite/ca/server-key.pem",
		CAKeyStoreDir:        "/var/lib/sovereignite/ca",
	}
}

func TestValidateTransitionValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		from  NetworkState
		to    NetworkState
	}{
		{"boot to dhcp_discovery", StateBoot, StateDHCPDiscovery},
		{"dhcp_discovery to connected", StateDHCPDiscovery, StateConnected},
		{"dhcp_discovery to dhcp_failed", StateDHCPDiscovery, StateDHCPFailed},
		{"dhcp_failed to static", StateDHCPFailed, StateStatic},
		{"static to hotspot_mode", StateStatic, StateHotspotMode},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := ValidateTransition(test.from, test.to); err != nil {
				t.Errorf("ValidateTransition(%q, %q) = %v, want nil",
					test.from, test.to, err)
			}
		})
	}
}

func TestValidateTransitionSelfTransition(t *testing.T) {
	t.Parallel()

	if err := ValidateTransition(StateBoot, StateBoot); err == nil {
		t.Error("ValidateTransition accepted self-transition, want error")
	}
}

func TestValidateTransitionInvalid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		from NetworkState
		to   NetworkState
	}{
		{"connected to boot", StateConnected, StateBoot},
		{"hotspot to dhcp", StateHotspotMode, StateDHCPDiscovery},
		{"boot to connected", StateBoot, StateConnected},
		{"static to dhcp_discovery", StateStatic, StateDHCPDiscovery},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := ValidateTransition(test.from, test.to); err == nil {
				t.Errorf("ValidateTransition(%q, %q) = nil, want error",
					test.from, test.to)
			}
		})
	}
}

func TestValidateTransitionUnknownState(t *testing.T) {
	t.Parallel()

	if err := ValidateTransition("unknown", StateBoot); err == nil {
		t.Error("ValidateTransition accepted unknown source state, want error")
	}
}

func TestValidWiFiSecurityModes(t *testing.T) {
	t.Parallel()

	if !ValidWiFiSecurityModes[SecurityModeWPA2Enterprise] {
		t.Error("WPA2-Enterprise not in valid modes")
	}
	if !ValidWiFiSecurityModes[SecurityModeWPA3Enterprise] {
		t.Error("WPA3-Enterprise not in valid modes")
	}
	if ValidWiFiSecurityModes["wpa-psk"] {
		t.Error("WPA-PSK should not be in valid modes")
	}
	if ValidWiFiSecurityModes["open"] {
		t.Error("open should not be in valid modes")
	}
}

func TestHotspotConfigValid(t *testing.T) {
	t.Parallel()

	config := validHotspotConfig()
	if err := config.Validate(); err != nil {
		t.Errorf("valid config Validate() = %v, want nil", err)
	}
}

func TestHotspotConfigRequiresPeerID(t *testing.T) {
	t.Parallel()

	config := validHotspotConfig()
	config.DevicePeerID = ""
	if err := config.Validate(); err == nil {
		t.Error("Validate() accepted empty peer ID, want error")
	}
}

func TestHotspotConfigRequiresTrustDomain(t *testing.T) {
	t.Parallel()

	config := validHotspotConfig()
	config.TrustDomain = ""
	if err := config.Validate(); err == nil {
		t.Error("Validate() accepted empty trust domain, want error")
	}
}

func TestHotspotConfigSSIDBounds(t *testing.T) {
	t.Parallel()

	config := validHotspotConfig()

	config.SSID = ""
	if err := config.Validate(); err == nil {
		t.Error("Validate() accepted empty SSID, want error")
	}

	config.SSID = "A"
	if err := config.Validate(); err != nil {
		t.Errorf("Validate() rejected single-char SSID: %v", err)
	}

	longSSID := ""
	for i := 0; i < 33; i++ {
		longSSID += "A"
	}
	config.SSID = longSSID
	if err := config.Validate(); err == nil {
		t.Error("Validate() accepted SSID > 32 chars, want error")
	}
}

func TestHotspotConfigRejectsInsecureSecurityModes(t *testing.T) {
	t.Parallel()

	config := validHotspotConfig()

	insecureModes := []WiFiSecurityMode{
		"wpa-psk",
		"wpa2-psk",
		"wpa3-psk",
		"open",
		"wep",
		"",
	}

	for _, mode := range insecureModes {
		config.SecurityMode = mode
		if err := config.Validate(); err == nil {
			t.Errorf("Validate() accepted insecure mode %q, want error", mode)
		}
	}
}

func TestHotspotConfigChannelBounds(t *testing.T) {
	t.Parallel()

	config := validHotspotConfig()

	config.Channel = 0
	if err := config.Validate(); err == nil {
		t.Error("Validate() accepted channel 0, want error")
	}

	config.Channel = 15
	if err := config.Validate(); err == nil {
		t.Error("Validate() accepted channel 15, want error")
	}

	config.Channel = 6
	if err := config.Validate(); err != nil {
		t.Errorf("Validate() rejected valid channel 6: %v", err)
	}
}

func TestHotspotConfigRequiresCountryCode(t *testing.T) {
	t.Parallel()

	config := validHotspotConfig()

	config.CountryCode = ""
	if err := config.Validate(); err == nil {
		t.Error("Validate() accepted empty country code, want error")
	}

	config.CountryCode = "USA"
	if err := config.Validate(); err == nil {
		t.Error("Validate() accepted 3-char country code, want error")
	}
}

func TestHotspotConfigRequiresCertPaths(t *testing.T) {
	t.Parallel()

	config := validHotspotConfig()
	config.CAMertificatePath = ""
	if err := config.Validate(); err == nil {
		t.Error("Validate() accepted empty CA cert path, want error")
	}

	config = validHotspotConfig()
	config.ServerCertificatePath = ""
	if err := config.Validate(); err == nil {
		t.Error("Validate() accepted empty server cert path, want error")
	}

	config = validHotspotConfig()
	config.ServerKeyPath = ""
	if err := config.Validate(); err == nil {
		t.Error("Validate() accepted empty server key path, want error")
	}
}

func TestHotspotConfigRequiresAbsolutePaths(t *testing.T) {
	t.Parallel()

	config := validHotspotConfig()

	config.CAMertificatePath = "relative/ca.pem"
	if err := config.Validate(); err == nil {
		t.Error("Validate() accepted relative CA cert path, want error")
	}

	config = validHotspotConfig()
	config.ServerCertificatePath = "relative/server.pem"
	if err := config.Validate(); err == nil {
		t.Error("Validate() accepted relative server cert path, want error")
	}

	config = validHotspotConfig()
	config.ServerKeyPath = "relative/server-key.pem"
	if err := config.Validate(); err == nil {
		t.Error("Validate() accepted relative server key path, want error")
	}
}

func TestHotspotConfigRequiresCAKeyStoreDir(t *testing.T) {
	t.Parallel()

	config := validHotspotConfig()
	config.CAKeyStoreDir = ""
	if err := config.Validate(); err == nil {
		t.Error("Validate() accepted empty CA key store dir, want error")
	}

	config.CAKeyStoreDir = "relative/dir"
	if err := config.Validate(); err == nil {
		t.Error("Validate() accepted relative CA key store dir, want error")
	}
}

func TestNewGeneratorValidatesConfig(t *testing.T) {
	t.Parallel()

	config := validHotspotConfig()
	config.DevicePeerID = ""
	if _, err := NewGenerator(config); err == nil {
		t.Error("NewGenerator accepted invalid config, want error")
	}
}

func TestNewGeneratorAcceptsValidConfig(t *testing.T) {
	t.Parallel()

	config := validHotspotConfig()
	gen, err := NewGenerator(config)
	if err != nil {
		t.Fatalf("NewGenerator() = %v, want nil", err)
	}
	if gen == nil {
		t.Fatal("NewGenerator() returned nil generator")
	}
}

func TestGenerateHostapdConfigWPA2Enterprise(t *testing.T) {
	t.Parallel()

	config := validHotspotConfig()
	config.SecurityMode = SecurityModeWPA2Enterprise
	gen, err := NewGenerator(config)
	if err != nil {
		t.Fatalf("NewGenerator() = %v", err)
	}

	conf := gen.GenerateHostapdConfig()
	if conf.Version != NetworkVersion {
		t.Errorf("Version = %d, want %d", conf.Version, NetworkVersion)
	}
	if conf.Interface != "wlan0" {
		t.Errorf("Interface = %q, want %q", conf.Interface, "wlan0")
	}
	if conf.SSID != "Sovereignite" {
		t.Errorf("SSID = %q, want %q", conf.SSID, "Sovereignite")
	}
	if conf.SecurityMode != SecurityModeWPA2Enterprise {
		t.Errorf("SecurityMode = %q, want %q",
			conf.SecurityMode, SecurityModeWPA2Enterprise)
	}
	if conf.Channel != 6 {
		t.Errorf("Channel = %d, want 6", conf.Channel)
	}
	if conf.CountryCode != "US" {
		t.Errorf("CountryCode = %q, want %q", conf.CountryCode, "US")
	}
	if conf.CAMertificatePath != "/var/lib/sovereignite/ca/ca.pem" {
		t.Errorf("CAMertificatePath = %q, want %q",
			conf.CAMertificatePath, "/var/lib/sovereignite/ca/ca.pem")
	}
	if conf.EAPCACertificatePath != conf.CAMertificatePath {
		t.Errorf("EAPCACertificatePath = %q != CAMertificatePath %q",
			conf.EAPCACertificatePath, conf.CAMertificatePath)
	}
	if conf.EAPServerCertPath != conf.ServerCertificatePath {
		t.Errorf("EAPServerCertPath = %q != ServerCertificatePath %q",
			conf.EAPServerCertPath, conf.ServerCertificatePath)
	}
	if conf.EAPServerKeyPath != conf.ServerKeyPath {
		t.Errorf("EAPServerKeyPath = %q != ServerKeyPath %q",
			conf.EAPServerKeyPath, conf.ServerKeyPath)
	}
}

func TestGenerateHostapdConfigWPA3Enterprise(t *testing.T) {
	t.Parallel()

	config := validHotspotConfig()
	config.SecurityMode = SecurityModeWPA3Enterprise
	gen, err := NewGenerator(config)
	if err != nil {
		t.Fatalf("NewGenerator() = %v", err)
	}

	conf := gen.GenerateHostapdConfig()
	if conf.SecurityMode != SecurityModeWPA3Enterprise {
		t.Errorf("SecurityMode = %q, want %q",
			conf.SecurityMode, SecurityModeWPA3Enterprise)
	}
}

func TestGenerateWpaSupplicantConfigValid(t *testing.T) {
	t.Parallel()

	config := validHotspotConfig()
	gen, err := NewGenerator(config)
	if err != nil {
		t.Fatalf("NewGenerator() = %v", err)
	}

	conf, err := gen.GenerateWpaSupplicantConfig(
		"/var/lib/sovereignite/wifi/client.pem",
		"/var/lib/sovereignite/wifi/client-key.pem",
		"spiffe://bafybeigdyrzhk6dyp3wklsazmcei4rb4l5q3ci3dgbp2g5xu5e7xq4abcde/device/12D3KooWBhTbHvhCFPgRdgmfvGMNHxqgFMFyGRzEeMH2bMqFKFEi",
	)
	if err != nil {
		t.Fatalf("GenerateWpaSupplicantConfig() = %v", err)
	}
	if conf.Version != NetworkVersion {
		t.Errorf("Version = %d, want %d", conf.Version, NetworkVersion)
	}
	if conf.Interface != "wlan0" {
		t.Errorf("Interface = %q, want %q", conf.Interface, "wlan0")
	}
	if conf.SSID != "Sovereignite" {
		t.Errorf("SSID = %q, want %q", conf.SSID, "Sovereignite")
	}
	if conf.ClientCertificatePath != "/var/lib/sovereignite/wifi/client.pem" {
		t.Errorf("ClientCertificatePath = %q, want %q",
			conf.ClientCertificatePath, "/var/lib/sovereignite/wifi/client.pem")
	}
	if conf.CACertificatePath != "/var/lib/sovereignite/ca/ca.pem" {
		t.Errorf("CACertificatePath = %q, want %q",
			conf.CACertificatePath, "/var/lib/sovereignite/ca/ca.pem")
	}
}

func TestGenerateWpaSupplicantConfigRequiresClientCert(t *testing.T) {
	t.Parallel()

	config := validHotspotConfig()
	gen, err := NewGenerator(config)
	if err != nil {
		t.Fatalf("NewGenerator() = %v", err)
	}

	if _, err := gen.GenerateWpaSupplicantConfig(
		"",
		"/key.pem",
		"identity",
	); err == nil {
		t.Error("GenerateWpaSupplicantConfig() accepted empty client cert, want error")
	}
}

func TestGenerateWpaSupplicantConfigRequiresClientKey(t *testing.T) {
	t.Parallel()

	config := validHotspotConfig()
	gen, err := NewGenerator(config)
	if err != nil {
		t.Fatalf("NewGenerator() = %v", err)
	}

	if _, err := gen.GenerateWpaSupplicantConfig(
		"/cert.pem",
		"",
		"identity",
	); err == nil {
		t.Error("GenerateWpaSupplicantConfig() accepted empty client key, want error")
	}
}

func TestGenerateWpaSupplicantConfigRequiresIdentity(t *testing.T) {
	t.Parallel()

	config := validHotspotConfig()
	gen, err := NewGenerator(config)
	if err != nil {
		t.Fatalf("NewGenerator() = %v", err)
	}

	if _, err := gen.GenerateWpaSupplicantConfig(
		"/cert.pem",
		"/key.pem",
		"",
	); err == nil {
		t.Error("GenerateWpaSupplicantConfig() accepted empty identity, want error")
	}
}

func TestGenerateWpaSupplicantConfigRejectsRelativePaths(t *testing.T) {
	t.Parallel()

	config := validHotspotConfig()
	gen, err := NewGenerator(config)
	if err != nil {
		t.Fatalf("NewGenerator() = %v", err)
	}

	if _, err := gen.GenerateWpaSupplicantConfig(
		"relative/cert.pem",
		"/key.pem",
		"identity",
	); err == nil {
		t.Error("GenerateWpaSupplicantConfig() accepted relative client cert, want error")
	}

	if _, err := gen.GenerateWpaSupplicantConfig(
		"/cert.pem",
		"relative/key.pem",
		"identity",
	); err == nil {
		t.Error("GenerateWpaSupplicantConfig() accepted relative client key, want error")
	}
}

func TestWiFiClientCertificateTemplateValid(t *testing.T) {
	t.Parallel()

	config := validHotspotConfig()
	gen, err := NewGenerator(config)
	if err != nil {
		t.Fatalf("NewGenerator() = %v", err)
	}

	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.Add(365 * 24 * time.Hour)
	cert, err := gen.WiFiClientCertificateTemplate(
		"rel_001",
		"spiffe://bafybeigdyrzhk6dyp3wklsazmcei4rb4l5q3ci3dgbp2g5xu5e7xq4abcde/device/12D3KooWBhTbHvhCFPgRdgmfvGMNHxqgFMFyGRzEeMH2bMqFKFEi",
		big.NewInt(1),
		notBefore,
		notAfter,
	)
	if err != nil {
		t.Fatalf("WiFiClientCertificateTemplate() = %v", err)
	}
	if cert == nil {
		t.Fatal("WiFiClientCertificateTemplate() returned nil")
	}
	if cert.IsCA {
		t.Error("template IsCA = true, want false")
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("template missing KeyUsageDigitalSignature")
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("ExtKeyUsage = %v, want [ClientAuth]", cert.ExtKeyUsage)
	}
	if cert.SerialNumber.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("SerialNumber = %v, want 1", cert.SerialNumber)
	}
	if !cert.NotBefore.Equal(notBefore) {
		t.Errorf("NotBefore = %v, want %v", cert.NotBefore, notBefore)
	}
	if !cert.NotAfter.Equal(notAfter) {
		t.Errorf("NotAfter = %v, want %v", cert.NotAfter, notAfter)
	}
	if len(cert.URIs) != 1 {
		t.Fatalf("URIs length = %d, want 1", len(cert.URIs))
	}
	if cert.URIs[0].Scheme != "spiffe" {
		t.Errorf("URI Scheme = %q, want %q", cert.URIs[0].Scheme, "spiffe")
	}
}

func TestWiFiClientCertificateTemplateRequiresRelationshipID(t *testing.T) {
	t.Parallel()

	config := validHotspotConfig()
	gen, err := NewGenerator(config)
	if err != nil {
		t.Fatalf("NewGenerator() = %v", err)
	}

	if _, err := gen.WiFiClientCertificateTemplate(
		"",
		"spiffe://domain/device/peer",
		big.NewInt(1),
		time.Now(),
		time.Now().Add(time.Hour),
	); err == nil {
		t.Error("WiFiClientCertificateTemplate() accepted empty relationship ID, want error")
	}
}

func TestWiFiClientCertificateTemplateRequiresSPIFFEID(t *testing.T) {
	t.Parallel()

	config := validHotspotConfig()
	gen, err := NewGenerator(config)
	if err != nil {
		t.Fatalf("NewGenerator() = %v", err)
	}

	if _, err := gen.WiFiClientCertificateTemplate(
		"rel_001",
		"",
		big.NewInt(1),
		time.Now(),
		time.Now().Add(time.Hour),
	); err == nil {
		t.Error("WiFiClientCertificateTemplate() accepted empty SPIFFE ID, want error")
	}
}

func TestWiFiClientCertificateTemplateRequiresSerialNumber(t *testing.T) {
	t.Parallel()

	config := validHotspotConfig()
	gen, err := NewGenerator(config)
	if err != nil {
		t.Fatalf("NewGenerator() = %v", err)
	}

	if _, err := gen.WiFiClientCertificateTemplate(
		"rel_001",
		"spiffe://domain/device/peer",
		nil,
		time.Now(),
		time.Now().Add(time.Hour),
	); err == nil {
		t.Error("WiFiClientCertificateTemplate() accepted nil serial, want error")
	}

	if _, err := gen.WiFiClientCertificateTemplate(
		"rel_001",
		"spiffe://domain/device/peer",
		big.NewInt(0),
		time.Now(),
		time.Now().Add(time.Hour),
	); err == nil {
		t.Error("WiFiClientCertificateTemplate() accepted zero serial, want error")
	}
}

func TestWiFiClientCertificateTemplateRequiresNotBefore(t *testing.T) {
	t.Parallel()

	config := validHotspotConfig()
	gen, err := NewGenerator(config)
	if err != nil {
		t.Fatalf("NewGenerator() = %v", err)
	}

	if _, err := gen.WiFiClientCertificateTemplate(
		"rel_001",
		"spiffe://domain/device/peer",
		big.NewInt(1),
		time.Time{},
		time.Now().Add(time.Hour),
	); err == nil {
		t.Error("WiFiClientCertificateTemplate() accepted zero notBefore, want error")
	}
}

func TestWiFiClientCertificateTemplateRequiresNotAfter(t *testing.T) {
	t.Parallel()

	config := validHotspotConfig()
	gen, err := NewGenerator(config)
	if err != nil {
		t.Fatalf("NewGenerator() = %v", err)
	}

	now := time.Now()
	if _, err := gen.WiFiClientCertificateTemplate(
		"rel_001",
		"spiffe://domain/device/peer",
		big.NewInt(1),
		now,
		now.Add(-time.Hour),
	); err == nil {
		t.Error("WiFiClientCertificateTemplate() accepted notAfter before notBefore, want error")
	}
}

func TestWiFiClientCertificateTemplateRejectsInvalidSPIFFEID(t *testing.T) {
	t.Parallel()

	config := validHotspotConfig()
	gen, err := NewGenerator(config)
	if err != nil {
		t.Fatalf("NewGenerator() = %v", err)
	}

	now := time.Now()
	if _, err := gen.WiFiClientCertificateTemplate(
		"rel_001",
		"not-a-spiffe-id",
		big.NewInt(1),
		now,
		now.Add(time.Hour),
	); err == nil {
		t.Error("WiFiClientCertificateTemplate() accepted invalid SPIFFE ID, want error")
	}
}

func TestHostapdConfigPath(t *testing.T) {
	t.Parallel()

	config := validHotspotConfig()
	gen, err := NewGenerator(config)
	if err != nil {
		t.Fatalf("NewGenerator() = %v", err)
	}

	expected := "/etc/hostapd/hostapd.conf"
	if got := gen.HostapdConfigPath(); got != expected {
		t.Errorf("HostapdConfigPath() = %q, want %q", got, expected)
	}
}

func TestWpaSupplicantConfigPath(t *testing.T) {
	t.Parallel()

	config := validHotspotConfig()
	gen, err := NewGenerator(config)
	if err != nil {
		t.Fatalf("NewGenerator() = %v", err)
	}

	expected := "/etc/wpa_supplicant/wpa_supplicant.conf"
	if got := gen.WpaSupplicantConfigPath(); got != expected {
		t.Errorf("WpaSupplicantConfigPath() = %q, want %q", got, expected)
	}
}

func TestCAMertificatePath(t *testing.T) {
	t.Parallel()

	config := validHotspotConfig()
	gen, err := NewGenerator(config)
	if err != nil {
		t.Fatalf("NewGenerator() = %v", err)
	}

	expected := "/var/lib/sovereignite/ca/ca.pem"
	if got := gen.CAMertificatePath(); got != expected {
		t.Errorf("CAMertificatePath() = %q, want %q", got, expected)
	}
}

func TestCAKeyStoreDir(t *testing.T) {
	t.Parallel()

	config := validHotspotConfig()
	gen, err := NewGenerator(config)
	if err != nil {
		t.Fatalf("NewGenerator() = %v", err)
	}

	expected := "/var/lib/sovereignite/ca"
	if got := gen.CAKeyStoreDir(); got != expected {
		t.Errorf("CAKeyStoreDir() = %q, want %q", got, expected)
	}
}

func TestNetworkStateString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		state    NetworkState
		expected string
	}{
		{StateBoot, "boot"},
		{StateDHCPDiscovery, "dhcp_discovery"},
		{StateConnected, "connected"},
		{StateDHCPFailed, "dhcp_failed"},
		{StateStatic, "static"},
		{StateHotspotMode, "hotspot_mode"},
	}

	for _, test := range tests {
		if string(test.state) != test.expected {
			t.Errorf("state %v string = %q, want %q",
				test.state, string(test.state), test.expected)
		}
	}
}

func TestFullStateTransitionPath(t *testing.T) {
	t.Parallel()

	path := []struct {
		from NetworkState
		to   NetworkState
	}{
		{StateBoot, StateDHCPDiscovery},
		{StateDHCPDiscovery, StateDHCPFailed},
		{StateDHCPFailed, StateStatic},
		{StateStatic, StateHotspotMode},
	}

	for _, step := range path {
		if err := ValidateTransition(step.from, step.to); err != nil {
			t.Errorf("transition %q -> %q: %v", step.from, step.to, err)
		}
	}
}

func TestSuccessfulDHCPTransitionPath(t *testing.T) {
	t.Parallel()

	path := []struct {
		from NetworkState
		to   NetworkState
	}{
		{StateBoot, StateDHCPDiscovery},
		{StateDHCPDiscovery, StateConnected},
	}

	for _, step := range path {
		if err := ValidateTransition(step.from, step.to); err != nil {
			t.Errorf("transition %q -> %q: %v", step.from, step.to, err)
		}
	}
}

func TestConnectedIsTerminal(t *testing.T) {
	t.Parallel()

	for _, target := range []NetworkState{
		StateBoot,
		StateDHCPDiscovery,
		StateDHCPFailed,
		StateStatic,
		StateHotspotMode,
	} {
		if err := ValidateTransition(StateConnected, target); err == nil {
			t.Errorf("transition from connected to %q should fail", target)
		}
	}
}

func TestHotspotModeIsTerminal(t *testing.T) {
	t.Parallel()

	for _, target := range []NetworkState{
		StateBoot,
		StateDHCPDiscovery,
		StateConnected,
		StateDHCPFailed,
		StateStatic,
	} {
		if err := ValidateTransition(StateHotspotMode, target); err == nil {
			t.Errorf("transition from hotspot_mode to %q should fail", target)
		}
	}
}

func TestGenerateWpaSupplicantConfigWPA3Enterprise(t *testing.T) {
	t.Parallel()

	config := validHotspotConfig()
	config.SecurityMode = SecurityModeWPA3Enterprise
	gen, err := NewGenerator(config)
	if err != nil {
		t.Fatalf("NewGenerator() = %v", err)
	}

	conf, err := gen.GenerateWpaSupplicantConfig(
		"/client.pem",
		"/client-key.pem",
		"spiffe://domain/device/peer",
	)
	if err != nil {
		t.Fatalf("GenerateWpaSupplicantConfig() = %v", err)
	}
	if conf.SecurityMode != SecurityModeWPA3Enterprise {
		t.Errorf("SecurityMode = %q, want %q",
			conf.SecurityMode, SecurityModeWPA3Enterprise)
	}
}
