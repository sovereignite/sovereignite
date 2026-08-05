package endpoint

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const (
	dirPerms  = 0o700
	filePerms = 0o600
)

type Endpoint struct {
	Service     string `json:"service"`
	Address     string `json:"address"`
	Port        int    `json:"port"`
	BootID      string `json:"boot_id"`
	PID         int    `json:"pid"`
	StartedAt   string `json:"started_at"`
	Ready       bool   `json:"ready"`
	MAC         string `json:"mac,omitempty"`
	Network     string `json:"network,omitempty"`
}

var RunDir = func() string {
	return "/run/sovereignite"
}

func ServiceDir(service string) string {
	return filepath.Join(RunDir(), service)
}

func EndpointPath(service string) string {
	return filepath.Join(ServiceDir(service), "endpoint.json")
}

func CurrentBootID() (string, error) {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", fmt.Errorf("read boot ID: %w", err)
	}
	return string(data[:len(data)-1]), nil
}

func Publish(ep Endpoint) error {
	if ep.Service == "" {
		return fmt.Errorf("service name is required")
	}
	bootID, err := CurrentBootID()
	if err != nil {
		return fmt.Errorf("get boot ID: %w", err)
	}
	ep.BootID = bootID
	if ep.StartedAt == "" {
		ep.StartedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if ep.PID == 0 {
		ep.PID = os.Getpid()
	}
	dir := ServiceDir(ep.Service)
	if err := os.MkdirAll(dir, dirPerms); err != nil {
		return fmt.Errorf("create directory %s: %w", dir, err)
	}
	data, err := json.Marshal(ep)
	if err != nil {
		return fmt.Errorf("marshal endpoint: %w", err)
	}
	tmp := EndpointPath(ep.Service) + ".tmp"
	if err := os.WriteFile(tmp, data, filePerms); err != nil {
		return fmt.Errorf("write temp endpoint: %w", err)
	}
	if err := os.Rename(tmp, EndpointPath(ep.Service)); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename endpoint: %w", err)
	}
	return nil
}

func Read(service string) (*Endpoint, error) {
	path := EndpointPath(service)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read endpoint %s: %w", path, err)
	}
	var ep Endpoint
	if err := json.Unmarshal(data, &ep); err != nil {
		return nil, fmt.Errorf("parse endpoint %s: %w", path, err)
	}
	return &ep, nil
}

func Validate(service string) (*Endpoint, error) {
	ep, err := Read(service)
	if err != nil {
		return nil, err
	}
	bootID, err := CurrentBootID()
	if err != nil {
		return nil, fmt.Errorf("get boot ID: %w", err)
	}
	if ep.BootID != bootID {
		return nil, fmt.Errorf("stale endpoint: boot ID mismatch (have %s, want %s)", ep.BootID, bootID)
	}
	info, err := os.Stat(EndpointPath(service))
	if err != nil {
		return nil, fmt.Errorf("stat endpoint: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("cannot stat endpoint file")
	}
	if stat.Uid != uint32(os.Getuid()) {
		return nil, fmt.Errorf("wrong owner: uid %d", stat.Uid)
	}
	if ep.PID != 0 {
		proc, err := os.FindProcess(ep.PID)
		if err == nil {
			if err := proc.Signal(syscall.Signal(0)); err != nil {
				return nil, fmt.Errorf("process %d not running", ep.PID)
			}
		}
	}
	return ep, nil
}

func Cleanup(service string) error {
	path := EndpointPath(service)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove endpoint %s: %w", path, err)
	}
	return nil
}

func ListenTCP(host string, port int) (net.Listener, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", addr, err)
	}
	return ln, nil
}
