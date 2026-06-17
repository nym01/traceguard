package main

import (
	"fmt"
	"strings"
	"syscall"
)

type Severity string

// Event is the unified shape all three monitors (exec, file_access,
// network) produce. Not every field is populated for every event type.
type Event struct {
	Type string // "exec" | "file_access" | "network"
	PID  uint32
	PPID uint32
	Comm string
	// ParentComm is the parent process's command name. Only populated for
	// exec events, captured in-kernel at the moment of the exec rather than
	// looked up afterward via /proc — by lookup time the parent may already
	// have exited, which would otherwise lose the name on fast-moving execs.
	ParentComm string
	Filename   string
	Flags      uint32
	DstIP      string
	DstPort    uint16
}

type RuleConfig struct {
	ShellSpawn     ShellSpawnRule     `yaml:"shell_spawn"`
	SensitiveFiles SensitiveFilesRule `yaml:"sensitive_files"`
	ReadonlyWrites ReadonlyWritesRule `yaml:"readonly_writes"`
	NetworkAnomaly NetworkAnomalyRule `yaml:"network_anomaly"`
}

type ShellSpawnRule struct {
	Enabled        bool     `yaml:"enabled"`
	Severity       Severity `yaml:"severity"`
	ShellNames     []string `yaml:"shell_names"`
	AllowedParents []string `yaml:"allowed_parents"`
}

type SensitiveFilesRule struct {
	Enabled        bool     `yaml:"enabled"`
	Severity       Severity `yaml:"severity"`
	Paths          []string `yaml:"paths"`
	PathSubstrings []string `yaml:"path_substrings"`
}

type ReadonlyWritesRule struct {
	Enabled           bool     `yaml:"enabled"`
	Severity          Severity `yaml:"severity"`
	ProtectedPrefixes []string `yaml:"protected_prefixes"`
}

type NetworkAnomalyRule struct {
	Enabled      bool     `yaml:"enabled"`
	Severity     Severity `yaml:"severity"`
	AllowedPorts []int    `yaml:"allowed_ports"`
}

type Alert struct {
	Rule     string
	Severity Severity
	Message  string
	PID      uint32
	Comm     string
	Filename string
	Dst      string
}

func contains(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

func evalShellSpawn(e Event, r ShellSpawnRule) *Alert {
	if !r.Enabled || e.Type != "exec" || !contains(r.ShellNames, e.Comm) {
		return nil
	}
	if contains(r.AllowedParents, e.ParentComm) {
		return nil
	}
	return &Alert{
		Rule:     "unexpected-shell-spawn",
		Severity: r.Severity,
		Message:  fmt.Sprintf("shell %q spawned by unexpected parent %q (ppid %d)", e.Comm, e.ParentComm, e.PPID),
		PID:      e.PID,
		Comm:     e.Comm,
	}
}

func evalSensitiveFiles(e Event, r SensitiveFilesRule) *Alert {
	if !r.Enabled || e.Type != "file_access" {
		return nil
	}
	hit := contains(r.Paths, e.Filename)
	if !hit {
		for _, sub := range r.PathSubstrings {
			if strings.Contains(e.Filename, sub) {
				hit = true
				break
			}
		}
	}
	if !hit {
		return nil
	}
	return &Alert{
		Rule:     "sensitive-file-access",
		Severity: r.Severity,
		Message:  fmt.Sprintf("%q accessed sensitive path %q", e.Comm, e.Filename),
		PID:      e.PID,
		Comm:     e.Comm,
		Filename: e.Filename,
	}
}

func evalReadonlyWrites(e Event, r ReadonlyWritesRule) *Alert {
	if !r.Enabled || e.Type != "file_access" {
		return nil
	}
	isWrite := e.Flags&(syscall.O_WRONLY|syscall.O_RDWR|syscall.O_CREAT|syscall.O_TRUNC|syscall.O_APPEND) != 0
	if !isWrite {
		return nil
	}
	var matched string
	for _, p := range r.ProtectedPrefixes {
		if strings.HasPrefix(e.Filename, p) {
			matched = p
			break
		}
	}
	if matched == "" {
		return nil
	}
	return &Alert{
		Rule:     "readonly-write",
		Severity: r.Severity,
		Message:  fmt.Sprintf("%q wrote to protected path %q (under %q)", e.Comm, e.Filename, matched),
		PID:      e.PID,
		Comm:     e.Comm,
		Filename: e.Filename,
	}
}

func evalNetworkAnomaly(e Event, r NetworkAnomalyRule) *Alert {
	if !r.Enabled || e.Type != "network" {
		return nil
	}
	for _, p := range r.AllowedPorts {
		if int(e.DstPort) == p {
			return nil
		}
	}
	dst := fmt.Sprintf("%s:%d", e.DstIP, e.DstPort)
	return &Alert{
		Rule:     "anomalous-outbound-connection",
		Severity: r.Severity,
		Message:  fmt.Sprintf("%q connected to unexpected port %d (%s)", e.Comm, e.DstPort, dst),
		PID:      e.PID,
		Comm:     e.Comm,
		Dst:      dst,
	}
}

// Evaluate runs an event against every enabled rule category and returns
// every alert that fired (usually zero or one, but nothing stops more
// than one category matching the same event).
func Evaluate(e Event, cfg RuleConfig) []*Alert {
	var alerts []*Alert
	for _, a := range []*Alert{
		evalShellSpawn(e, cfg.ShellSpawn),
		evalSensitiveFiles(e, cfg.SensitiveFiles),
		evalReadonlyWrites(e, cfg.ReadonlyWrites),
		evalNetworkAnomaly(e, cfg.NetworkAnomaly),
	} {
		if a != nil {
			alerts = append(alerts, a)
		}
	}
	return alerts
}
