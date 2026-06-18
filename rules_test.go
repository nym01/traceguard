package main

import (
	"os"
	"testing"
)

// TestMain points container-name resolution at an empty temp dir for the whole
// package, so rule tests neither walk nor depend on the real /sys/fs/cgroup.
// With no matching inode present, resolveContainerName cleanly returns "".
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "traceguard-cgroup-test")
	if err != nil {
		panic(err)
	}
	cgroupRoot = dir
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func testConfig() RuleConfig {
	return RuleConfig{
		ShellSpawn: ShellSpawnRule{
			Enabled:        true,
			Severity:       "high",
			ShellNames:     []string{"sh", "bash"},
			AllowedParents: []string{"sh", "bash", "sshd", "systemd", "login", "su", "sudo"},
		},
		SensitiveFiles: SensitiveFilesRule{
			Enabled:        true,
			Severity:       "critical",
			Paths:          []string{"/etc/shadow", "/etc/gshadow", "/etc/sudoers"},
			PathSubstrings: []string{".ssh/", "id_rsa", "id_ed25519"},
		},
		ReadonlyWrites: ReadonlyWritesRule{
			Enabled:           true,
			Severity:          "high",
			ProtectedPrefixes: []string{"/usr/", "/bin/", "/sbin/", "/lib/"},
		},
		NetworkAnomaly: NetworkAnomalyRule{
			Enabled:      true,
			Severity:     "medium",
			AllowedPorts: []int{80, 443, 53, 22},
		},
	}
}

func TestShellSpawn_UnexpectedParent_Fires(t *testing.T) {
	cfg := testConfig()
	// ParentComm is captured in-kernel at exec time, so the test sets it
	// directly rather than relying on a /proc lookup against a live PID.
	// "python3" is not in AllowedParents, so the rule should fire.
	e := Event{Type: "exec", Comm: "bash", PID: 999, PPID: 998, ParentComm: "python3"}
	alerts := Evaluate(e, cfg)
	found := false
	for _, a := range alerts {
		if a.Rule == "unexpected-shell-spawn" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected unexpected-shell-spawn alert, got %+v", alerts)
	}
}

func TestShellSpawn_AllowedParent_DoesNotFire(t *testing.T) {
	cfg := testConfig()
	// "sshd" is in AllowedParents, so a shell spawned by it is benign.
	e := Event{Type: "exec", Comm: "bash", PID: 999, PPID: 998, ParentComm: "sshd"}
	alerts := Evaluate(e, cfg)
	for _, a := range alerts {
		if a.Rule == "unexpected-shell-spawn" {
			t.Errorf("did not expect shell-spawn alert for an allowed parent, got %+v", a)
		}
	}
}

func TestShellSpawn_NonShellComm_DoesNotFire(t *testing.T) {
	cfg := testConfig()
	e := Event{Type: "exec", Comm: "ls", PID: 999, PPID: 1}
	alerts := Evaluate(e, cfg)
	for _, a := range alerts {
		if a.Rule == "unexpected-shell-spawn" {
			t.Errorf("ls is not a shell, should not fire shell-spawn rule, got %+v", a)
		}
	}
}

func TestSensitiveFile_ExactPath_Fires(t *testing.T) {
	cfg := testConfig()
	e := Event{Type: "file_access", Comm: "cat", Filename: "/etc/shadow"}
	alerts := Evaluate(e, cfg)
	if len(alerts) != 1 || alerts[0].Rule != "sensitive-file-access" {
		t.Errorf("expected exactly one sensitive-file-access alert, got %+v", alerts)
	}
}

func TestSensitiveFile_SSHKeySubstring_Fires(t *testing.T) {
	cfg := testConfig()
	e := Event{Type: "file_access", Comm: "cat", Filename: "/home/alice/.ssh/id_rsa"}
	alerts := Evaluate(e, cfg)
	if len(alerts) != 1 || alerts[0].Rule != "sensitive-file-access" {
		t.Errorf("expected sensitive-file-access alert for ssh key path, got %+v", alerts)
	}
}

func TestSensitiveFile_NormalPath_DoesNotFire(t *testing.T) {
	cfg := testConfig()
	e := Event{Type: "file_access", Comm: "cat", Filename: "/etc/hostname"}
	alerts := Evaluate(e, cfg)
	if len(alerts) != 0 {
		t.Errorf("did not expect any alert for /etc/hostname, got %+v", alerts)
	}
}

func TestReadonlyWrite_ProtectedPathWithWriteFlag_Fires(t *testing.T) {
	cfg := testConfig()
	e := Event{Type: "file_access", Comm: "malware", Filename: "/usr/bin/ls", Flags: 0x241}
	alerts := Evaluate(e, cfg)
	if len(alerts) != 1 || alerts[0].Rule != "readonly-write" {
		t.Errorf("expected readonly-write alert, got %+v", alerts)
	}
}

func TestReadonlyWrite_ProtectedPathReadOnly_DoesNotFire(t *testing.T) {
	cfg := testConfig()
	e := Event{Type: "file_access", Comm: "ld", Filename: "/usr/lib/libc.so", Flags: 0}
	alerts := Evaluate(e, cfg)
	if len(alerts) != 0 {
		t.Errorf("did not expect alert for a read-only open under a protected prefix, got %+v", alerts)
	}
}

func TestNetworkAnomaly_UnexpectedPort_Fires(t *testing.T) {
	cfg := testConfig()
	e := Event{Type: "network", Comm: "nc", DstIP: "10.0.0.5", DstPort: 4444}
	alerts := Evaluate(e, cfg)
	if len(alerts) != 1 || alerts[0].Rule != "anomalous-outbound-connection" {
		t.Errorf("expected anomalous-outbound-connection alert, got %+v", alerts)
	}
}

func TestNetworkAnomaly_AllowedPort_DoesNotFire(t *testing.T) {
	cfg := testConfig()
	e := Event{Type: "network", Comm: "curl", DstIP: "1.2.3.4", DstPort: 443}
	alerts := Evaluate(e, cfg)
	if len(alerts) != 0 {
		t.Errorf("did not expect alert for port 443, got %+v", alerts)
	}
}
