# TraceGuard — Project Overview

> Part of the TraceGuard handoff package. See also: [ARCHITECTURE](./ARCHITECTURE.md),
> [DOMAIN_MODEL](./DOMAIN_MODEL.md), [DEVELOPMENT_GUIDE](./DEVELOPMENT_GUIDE.md),
> [LLM_CONTEXT](./LLM_CONTEXT.md).

## 1. Executive Summary

### What this project does
TraceGuard is a **runtime security agent** (an EDR-style "tripwire") that watches
a Linux host at the kernel level using **eBPF** and raises structured JSON alerts
when suspicious activity matches a configurable rule set. It is conceptually a
small, focused clone of [Falco](https://falco.org).

It observes three kernel signals:

| Signal | Kernel attach point | eBPF source |
| --- | --- | --- |
| Process execution | `sched/sched_process_exec` tracepoint | `bpf/execmon.bpf.c` |
| File access (open) | `syscalls/sys_enter_openat` tracepoint | `bpf/filemon.bpf.c` |
| Outbound network connect | `syscalls/sys_enter_connect` tracepoint | `bpf/netmon.bpf.c` |

A single Go userspace binary loads these programs, drains their per-monitor ring
buffers, normalizes each raw kernel sample into a unified `Event`, runs every
event through a YAML-configured rule engine, and emits one JSON line per alert to
stdout (optionally mirrored to a log file and/or POSTed to a webhook).

### Primary purpose
Give **kernel-level visibility into every process exec, file open, and outbound
connection on a host with no per-application instrumentation** — nothing to inject
into the watched workloads and nothing they can opt out of — and turn that
telemetry into high-signal security alerts (reverse shells, credential theft,
tampering with read-only system paths, and anomalous C2/exfil connections).

### Target users
- **Security / detection engineers** running a host- or container-level tripwire.
- **Platform / SRE teams** wanting low-overhead runtime monitoring on Linux hosts
  or Kubernetes nodes.
- Secondarily, **learners** studying a clean, well-commented eBPF + Go reference
  implementation (the code and `DESIGN.md` are written to teach).

### Core features
- Three independent eBPF monitors sharing one pipeline pattern.
- Four hand-written detection rule categories (`rules.yaml`), each independently
  toggleable and tunable:
  - `unexpected-shell-spawn` (reverse-shell / post-exploitation)
  - `sensitive-file-access` (credential / secret reads)
  - `readonly-write` (tampering / persistence under protected prefixes)
  - `anomalous-outbound-connection` (C2 / exfil to unexpected ports)
- In-kernel noise pre-filter for the high-volume file monitor.
- Container-name resolution: cgroup id → Docker container name.
- Alert outputs: stdout, append-to-log-file, and Slack-compatible webhook.
- Dropped-event accounting (per-CPU counters surfaced every 30s and at shutdown).
- A self-scoring **detection validation suite** (`validate/`) and **CPU overhead**
  measurement scripts (`perf_test.sh`, `perf_steadystate.sh`).

### Current development status
**v1, detect-only, single-author project.** It detects and reports; it does
**not** block or remediate (enforcement via BPF LSM is an explicit, deferred v2
direction — see `README.md` "Scope"). Validation was run once locally with
reported results of 100% detection across 7 techniques and 0% false positives
across 8 benign workloads (`README.md`; the run is a single sequential pass, not a
statistical study — `DESIGN.md` §5). CI builds and tests on every push; Docker
images are pushed to ghcr.io from `main`/releases. The git history shows a recent
revert/re-merge of the container-name-resolution feature (it is currently **in**
HEAD — see commit `1b2fec8`).

### Technology stack
| Layer | Technology |
| --- | --- |
| Kernel programs | eBPF (C), CO-RE (Compile Once Run Everywhere), libbpf headers |
| eBPF ↔ Go bindings | [`cilium/ebpf`](https://github.com/cilium/ebpf) v0.21.0 + `bpf2go` codegen |
| Userspace | Go 1.26.4 |
| Config | YAML (`gopkg.in/yaml.v3` v3.0.1) |
| Build toolchain | clang/llvm, libbpf-dev, `go generate` |
| Packaging | Multi-stage Dockerfile (golang-bookworm builder → alpine runtime) |
| CI/CD | GitHub Actions → ghcr.io |
| License | GPL-3.0 (eBPF programs declare `Dual BSD/GPL`) |

### Key facts at a glance
- **~3,000 lines** total; ~1,400 hand-written Go/C, the rest bpf2go-generated.
- **No database, no HTTP server, no frontend.** It is a single long-running CLI
  daemon. (The only outbound HTTP is the optional webhook POST.)
- Must run as **root** (or with `CAP_BPF`/`CAP_SYS_ADMIN`) to load eBPF.
- Linux-only, x86_64-oriented build flags; kernel ≥ 5.3 assumed (bounded-loop
  verifier support — `DESIGN.md` §2).
</content>
</invoke>
