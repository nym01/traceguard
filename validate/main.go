package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// buildTestCases returns the fixed validation suite: a spread of attacks
// (including evasion / edge-case variants) plus benign activity that probes
// the boundaries of each rule.
//
// Two execution styles appear below:
//   - Some attack commands are wrapped as ["bash", "-c", "<string>"] so that
//     shell features (&&, ;, redirects, quoting) work through exec.Command.
//   - Everything that needs no host shell features is run as direct argv.
//     This matters especially for the benign cases AND for the shell-spawn
//     attacks: wrapping a command in a host "bash -c" makes the validator
//     itself spawn a host-level bash whose parent is traceguard-validate,
//     which trips unexpected-shell-spawn. For benign cases that would be a
//     false-positive artifact; for the zsh/shell attacks it would let the
//     test "pass" off the host bash rather than the in-container shell we
//     actually mean to detect. So those run as direct argv.
//
// Note on the container cases: a `docker run`/`docker exec` whose entrypoint
// is bash/sh/zsh trips unexpected-shell-spawn on its own, because at the host
// level the shell's parent is containerd-shim, which isn't an allowed parent.
// That's real and expected. So the BENIGN container cases use a non-shell
// entrypoint (echo/cat/ls/cp) — those binaries never match shell_names
// regardless of parent — to keep them from polluting the false-positive
// measurement.
//
// The traceguard-victim container (a long-lived `sleep 300` box with zsh
// pre-installed) is created once in main() before the timed loop starts;
// the docker-exec cases below reuse it. See setupVictimContainer.
func buildTestCases() []TestCase {
	return []TestCase{
		// --- Attacks ---
		{
			Name:       "reverse-shell-in-container",
			Category:   "attack",
			ExpectRule: "unexpected-shell-spawn",
			// Attacker with a foothold in an already-running container spawns
			// a shell — more realistic than a bare `docker run sh`. Run as
			// direct argv so the detection comes from the in-container bash,
			// not a host-level wrapper shell.
			Cmd: []string{"docker", "exec", "traceguard-victim", "bash", "-c", "id"},
		},
		{
			Name:       "shell-evasion-zsh",
			Category:   "attack",
			ExpectRule: "unexpected-shell-spawn",
			// zsh is a common interactive shell that went entirely undetected
			// until it was added to shell_names. Pre-installed in setup so the
			// exec is fast and lands inside this test's window.
			Cmd: []string{"docker", "exec", "traceguard-victim", "zsh", "-c", "id"},
		},
		{
			Name:       "read-etc-shadow",
			Category:   "attack",
			ExpectRule: "sensitive-file-access",
			Cmd:        []string{"bash", "-c", "docker run --rm ubuntu:24.04 cat /etc/shadow"},
		},
		{
			Name:       "credential-file-evasion",
			Category:   "attack",
			ExpectRule: "sensitive-file-access",
			// Cloud credential theft. The file need not exist — the open()
			// attempt against a path containing ".aws/" is what fires the
			// rule, regardless of whether the read succeeds. comm=cat.
			Cmd: []string{"docker", "run", "--rm", "ubuntu:24.04", "cat", "/root/.aws/credentials"},
		},
		{
			Name:       "privesc-write-etc-passwd",
			Category:   "attack",
			ExpectRule: "readonly-write",
			Cmd: []string{"bash", "-c",
				`docker run --rm ubuntu:24.04 bash -c "echo 'pwned::0:0::/root:/bin/bash' >> /etc/passwd"`},
		},
		{
			Name:       "package-manager-write",
			Category:   "attack",
			ExpectRule: "readonly-write",
			// comm=cp, no shell entrypoint involved: shows the rule flags ANY
			// write under a protected prefix (/usr/), independent of who does
			// it. This is the same dual-use tradeoff Falco's default ruleset
			// accepts — a real deployment would allowlist legitimate package
			// managers by comm name (noted in the report).
			Cmd: []string{"docker", "run", "--rm", "ubuntu:24.04", "cp", "/etc/hostname", "/usr/local/bin/sample-tool"},
		},
		{
			Name:       "suspicious-outbound-connection",
			Category:   "attack",
			ExpectRule: "anomalous-outbound-connection",
			Cmd: []string{"bash", "-c",
				`docker run --rm ubuntu:24.04 timeout 3 bash -c "exec 3<>/dev/tcp/45.33.32.156/4444" 2>/dev/null; true`},
		},

		// --- Benign: a mix of host-direct and non-shell-entrypoint containers ---
		// These are run as direct argv (NOT wrapped in "bash -c"): wrapping
		// them would make the validator itself spawn a host-level bash whose
		// parent is traceguard-validate, tripping unexpected-shell-spawn and
		// contaminating the false-positive measurement with a test artifact.
		// None of these need shell features, so direct exec is both correct
		// and representative.
		{Name: "ls-tmp", Category: "benign", Cmd: []string{"ls", "/tmp"}},
		{Name: "cat-hostname", Category: "benign", Cmd: []string{"cat", "/etc/hostname"}},
		{Name: "curl-example", Category: "benign", Cmd: []string{"curl", "-s", "http://example.com", "-o", "/dev/null"}},
		{Name: "ps-aux", Category: "benign", Cmd: []string{"ps", "aux"}},
		{Name: "container-echo", Category: "benign", Cmd: []string{"docker", "run", "--rm", "ubuntu:24.04", "echo", "hello"}},
		{Name: "container-cat-hostname", Category: "benign", Cmd: []string{"docker", "run", "--rm", "ubuntu:24.04", "cat", "/etc/hostname"}},
		{
			Name:     "list-ssh-dir",
			Category: "benign",
			// comm=ls, not a shell; and the path "/root/.ssh" has no trailing
			// slash, so it does NOT match the ".ssh/" substring. Confirms the
			// rule is scoped to files inside .ssh, not the directory entry.
			Cmd: []string{"docker", "run", "--rm", "ubuntu:24.04", "ls", "-la", "/root/.ssh"},
		},
		{
			Name:     "write-outside-protected-dirs",
			Category: "benign",
			// comm=cp writing to /tmp — direct contrast with
			// package-manager-write: writes outside the protected prefixes
			// correctly stay quiet.
			Cmd: []string{"docker", "run", "--rm", "ubuntu:24.04", "cp", "/etc/hostname", "/tmp/benign-copy"},
		},
	}
}

// runTestCase runs one test case's command and records the wall-clock
// window during which its alerts could appear. The command's own
// error/exit code is intentionally ignored: a failed attempt (e.g.
// "Permission denied" reading /etc/shadow) is still an attempt that
// traceguard should have observed. We score on alerts, not exit codes.
// The 1.5s sleep lets the event propagate through the ring buffer -> Go
// -> rule eval -> log write pipeline before we close the window.
func runTestCase(tc TestCase) TestResult {
	tr := TestResult{TestCase: tc}
	tr.Started = time.Now()
	_ = exec.Command(tc.Cmd[0], tc.Cmd[1:]...).Run()
	time.Sleep(1500 * time.Millisecond)
	tr.Ended = time.Now()
	return tr
}

// setupVictimContainer creates the long-lived traceguard-victim container and
// installs zsh into it ONCE, before any timed test runs. apt-get install takes
// 15-30s — far longer than runTestCase's 1500ms post-command buffer — so doing
// it inside a timed test would let the window close before the real exec fires.
// Doing it here means the shell-spawn alerts from the install's own bash land
// outside every test window and can't contaminate the measurement.
func setupVictimContainer() {
	fmt.Println("Setup: (re)creating traceguard-victim and installing zsh (this takes ~15-30s)...")
	_ = exec.Command("bash", "-c", "docker rm -f traceguard-victim 2>/dev/null").Run()
	_ = exec.Command("docker", "run", "-d", "--name", "traceguard-victim", "ubuntu:24.04", "sleep", "300").Run()
	time.Sleep(1 * time.Second)
	_ = exec.Command("docker", "exec", "traceguard-victim", "bash", "-c",
		"apt-get update -qq && apt-get install -qq -y zsh").Run()
}

func main() {
	// -log MUST match the path traceguard was started with via -log-file.
	logFlag := flag.String("log", "validation.log", "path to traceguard's log file (must match traceguard's -log-file)")
	flag.Parse()

	setupVictimContainer()

	cases := buildTestCases()
	results := make([]TestResult, 0, len(cases))
	for _, tc := range cases {
		fmt.Printf("Running: %s...\n", tc.Name)
		results = append(results, runTestCase(tc))
	}

	// Give the final test's alerts a moment to finish flushing to the log.
	time.Sleep(1 * time.Second)

	alerts, err := loadAlerts(*logFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "loading alerts from %q: %v\n", *logFlag, err)
		fmt.Fprintln(os.Stderr, "(does -log match the path traceguard was started with via -log-file?)")
		os.Exit(1)
	}

	for i := range results {
		scoreTestResult(&results[i], alerts)
	}

	fmt.Println()
	fmt.Print(buildReport(results).String())
}
