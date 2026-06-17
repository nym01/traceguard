# TraceGuard

TraceGuard is a runtime security agent that watches process execution, file
access, and outbound network connections at the kernel level using eBPF, in the
spirit of [Falco](https://falco.org). It attaches to kernel tracepoints, streams
the resulting telemetry into a single Go process, runs each event through a
YAML-configured rule engine, and emits a structured JSON alert whenever a rule
matches. v1 is **detect-only**: it observes and reports, it does not block.

## Architecture

Three small eBPF programs run in the kernel, one per signal:

| Monitor  | Attach point                              | Source                |
| -------- | ----------------------------------------- | --------------------- |
| `execmon` | `sched/sched_process_exec` tracepoint     | `bpf/execmon.bpf.c`   |
| `filemon` | `syscalls/sys_enter_openat` tracepoint    | `bpf/filemon.bpf.c`   |
| `netmon`  | `syscalls/sys_enter_connect` tracepoint   | `bpf/netmon.bpf.c`    |

Each program writes its events into its own `BPF_MAP_TYPE_RINGBUF` ring buffer.
A single Go binary opens a `ringbuf.Reader` per buffer and drains all three
concurrently — one reader goroutine per monitor — decoding each raw sample into
a unified `Event` and fanning them onto one shared channel. A single consumer
goroutine runs every event through the rule engine (`rules.go`, configured by
`rules.yaml`) and writes one JSON object per alert to stdout, optionally
mirrored to a log file and/or POSTed to a webhook.

Why eBPF: it gives kernel-level visibility into every process, open, and connect
on the host with **no per-application instrumentation** — nothing to inject into
the workloads being watched, and nothing they can opt out of.

## Quick start

TraceGuard loads eBPF programs, so it must run as root (or with the right
capabilities — see below).

### Bare binary

```sh
go generate ./...                 # bpf2go: compile the .bpf.c programs (needs clang)
go build -o traceguard .
sudo ./traceguard
```

> The committed repo already includes the bpf2go-generated `.go`/`.o` artifacts,
> so `go build` alone works without clang. Re-run `go generate` only if you
> change a `bpf/*.bpf.c` source.

### Docker

```sh
docker build -t traceguard .
docker run --rm --privileged \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  -v /sys/kernel/debug:/sys/kernel/debug:rw \
  traceguard
```

Why each piece is required:

- **`--privileged`** — loading eBPF programs needs `CAP_BPF` / `CAP_SYS_ADMIN`.
  (You can narrow this to those specific capabilities instead of full
  `--privileged` in a hardened deployment.)
- **`-v /sys/kernel/btf:...:ro`** — the programs are built with CO-RE
  (Compile Once, Run Everywhere); the kernel's BTF is what their field offsets
  are relocated against at load time on the target host.
- **`-v /sys/kernel/debug:...:rw`** — tracepoint attachment goes through
  `perf_event_open`, which needs debugfs/tracefs mounted.

### Flags

| Flag        | Default        | Meaning                                                       |
| ----------- | -------------- | ------------------------------------------------------------- |
| `-rules`    | `rules.yaml`   | Path to the YAML rule-config file.                            |
| `-verbose`  | off            | Also print the raw telemetry stream, not just alerts.         |
| `-log-file` | _(stdout only)_| Append all output to this file in addition to stdout.        |
| `-webhook`  | _(disabled)_   | POST each alert as JSON to this URL (Slack-compatible shape). |

## Scope: detect-only in v1

TraceGuard v1 **detects and reports; it does not block or remediate.** This is a
deliberate scope boundary, not a missing feature. Getting detection demonstrably
right — high recall on real techniques, near-zero false positives on benign
activity — is the foundation everything else stands on, and it is valuable on its
own as a tripwire.

Enforcement (e.g. BPF LSM hooks that can deny an `execve`, `open`, or `connect`
inline) is a real and intended future direction, but it is deliberately
deferred. Blocking is strictly riskier: a bad block rule doesn't just produce a
noisy alert, it can hang or crash a production system. Enforcement belongs
*after* detection is proven solid, not before it.

## Detection rules

Rules live in `rules.yaml`; each category can be toggled and tuned independently.

### `unexpected-shell-spawn`
Fires when a shell is `exec`'d by a parent that isn't on the allowlist — the
classic reverse-shell / post-exploitation signal.
- `shell_names`: process names treated as shells (`sh`, `bash`, `zsh`).
- `allowed_parents`: parent comms that may legitimately spawn a shell
  (`sshd`, `systemd`, `login`, `su`, `sudo`, …).

### `sensitive-file-access`
Fires when a process opens a credential or secret file.
- `paths`: exact paths (`/etc/shadow`, `/etc/gshadow`, `/etc/sudoers`).
- `path_substrings`: markers matched anywhere in the path
  (`.ssh/`, `id_rsa`, `id_ed25519`, `.pem`, `.aws/`) — so SSH keys and cloud
  credentials are caught wherever they live, not just under `/etc/`.

### `readonly-write`
Fires when a process opens a file for writing under a directory that should be
read-only at runtime (a tampering / persistence signal).
- `protected_prefixes`: `/usr/`, `/bin/`, `/sbin/`, `/lib/`, `/etc/`.

### `anomalous-outbound-connection`
Fires on an IPv4 `connect()` to a destination port outside the expected set
(reverse-shell callback, C2 beaconing, exfil).
- `allowed_ports`: ports considered normal (`80`, `443`, `53`, `22`).

## Validation results

From a single run of the validation suite (`validate/`):

- **100% detection across 7 attack techniques**, including two deliberate
  evasion attempts:
  - a shell name outside the usual `sh`/`bash` set (`zsh`), which went
    undetected until `zsh` was added to `shell_names`;
  - a credential file read from a path outside `/etc/` (`/root/.aws/credentials`).
- **0% false positives across 8 benign workloads**, including container
  startups (`docker run ... echo`, `... cat /etc/hostname`) and boundary cases
  designed to sit right next to a rule without tripping it (e.g. `ls /root/.ssh`
  — the directory entry, which has no trailing `.ssh/`, so it correctly does not
  match — and a `cp` write to `/tmp`, just outside the protected prefixes).

The composition matters more than the headline percentages: the suite passes
*because* it includes the evasion variants and the near-miss benign cases, not
in spite of their absence.

Performance overhead (measured with `perf_test.sh` / `perf_steadystate.sh`):

- **~5.23% CPU** at **100% event capture** under a burst of 2000 `execve`s
  (~700/s) in **`-verbose` mode** — every event marshaled and written to the log.
- **<0.5% CPU** in **steady-state, alerts-only mode** — the mode it actually
  runs in day to day, where unmatched events fire no rule and produce no output.

## Known limitations

These are real, specific gaps, documented so a reader knows exactly what v1 does
and doesn't see:

- **Container shell attribution is comm-name-based.** Parent matching uses the
  parent's command name, which cannot distinguish a container's own legitimate
  entrypoint shell from a `docker exec` shell *into that same container* — at the
  host level both share the same parent (`containerd-shim`). A real fix needs
  per-cgroup lineage tracking, not just comm names.
- **`openat()` only, not legacy `open()`.** Modern glibc funnels essentially all
  opens through `openat`, so coverage is high, but it is not 100% complete.
- **IPv4 only.** `netmon` bails out after the `AF_INET` check; IPv6 and
  `AF_UNIX` connections are not observed.
- **No cross-monitor correlation.** A credential read followed by an outbound
  connection from the same PID is two independent alerts today, not one elevated
  "attack chain" alert.
- **No `chmod`/`fchmod`, `ptrace`, or module-load coverage** — so the SUID-bit
  backdoor technique, process-injection via `ptrace`, and rootkit installation
  via kernel module loading are currently blind spots.
- **`readonly-write`'s `/usr/` coverage is intentionally dual-use.** A real
  deployment that runs package managers writing under `/usr/` would need to
  allowlist them by comm name. This is the same tradeoff Falco's own default
  ruleset accepts — a tuning step, not a defect.

## Possible v2 directions

- Event correlation / attack-chain detection across monitors (turn the
  credential-read-then-connect sequence into one elevated alert).
- Per-cgroup container lineage tracking to fix the `containerd-shim`
  attribution limitation.
- A head-to-head benchmark against a real Falco install on the same machine and
  attack suite.
- `chmod`/`ptrace`/module-load coverage for the techniques listed above.

## Project structure

Hand-written sources:

```
main.go                 # pipeline: load/attach eBPF, drain ring buffers, print alerts
rules.go                # Event model + the four rule evaluators (Evaluate)
rules_test.go           # unit tests for the rule engine
rules.yaml              # rule configuration (the four categories above)
webhook.go              # optional Slack-compatible webhook sender
webhook_test.go         # webhook sender tests
bpf/execmon.bpf.c       # process-exec eBPF program
bpf/filemon.bpf.c       # file-access eBPF program (+ in-kernel noise filter)
bpf/netmon.bpf.c        # network-connect eBPF program
validate/               # detection validation harness (attack/benign suite + scorer)
perf_test.sh            # CPU overhead measurement, verbose mode
perf_steadystate.sh     # CPU overhead measurement, alerts-only mode
Dockerfile              # multi-stage build (clang+bpf2go -> scratch-ish runtime)
.github/workflows/ci.yml # CI: vet/test/build, plus build/push image to ghcr.io
```

bpf2go-generated, **committed but not hand-edited**:

```
execmon_bpfel.go  execmon_bpfeb.go  execmon_bpfel.o  execmon_bpfeb.o
filemon_bpfel.go  filemon_bpfeb.go  filemon_bpfel.o  filemon_bpfeb.o
netmon_bpfel.go   netmon_bpfeb.go   netmon_bpfel.o   netmon_bpfeb.o
```

These are produced by `go generate` (bpf2go) from the `bpf/*.bpf.c` sources —
the `_bpfel`/`_bpfeb` split is little- vs big-endian. They are committed so the
repo builds with a plain `go build` on a machine that has neither clang nor
bpf2go installed. Don't edit them by hand; change the `.bpf.c` source and
re-run `go generate`.

## License

Licensed under the GNU General Public License v3.0 (GPL-3.0) — see the
[`LICENSE`](./LICENSE) file for the full text. This matches its sibling project
**[Tracebox](https://github.com/nym01/Tracebox)**, and is consistent with the
`Dual BSD/GPL` declaration the eBPF programs themselves carry. See `DESIGN.md`
for the engineering rationale behind the architecture and rules.
