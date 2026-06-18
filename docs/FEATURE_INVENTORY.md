# TraceGuard — Feature Inventory

> Every identifiable feature with its files, dependencies, user-facing behavior,
> and implementation summary. Citations: `file:line`.

## F1 — Process-execution monitoring
- **Description:** Emits one event per successful `execve`/`execveat`.
- **Files:** `bpf/execmon.bpf.c`, `execmon_bpf{el,eb}.go/.o`, `main.go` (load/attach/`decodeExec`).
- **Dependencies:** `sched/sched_process_exec` tracepoint, cilium/ebpf, CO-RE/BTF.
- **User-facing:** `exec` events (verbose) / `unexpected-shell-spawn` alerts.
- **Implementation:** hooks tracepoint; reads pid/ppid/cgroup/comm/parent_comm
  in-kernel + filename from `__data_loc`; submits to 16 MiB ring buffer.

## F2 — File-access monitoring with in-kernel noise filter
- **Description:** Emits selected `openat` events (writes, `/etc/` reads,
  credential-marked reads).
- **Files:** `bpf/filemon.bpf.c` (`has_sensitive_marker` :82), `filemon_bpf*`, `main.go` `decodeFile`.
- **Dependencies:** `syscalls/sys_enter_openat`, `bpf_probe_read_user_str`.
- **User-facing:** `sensitive-file-access` and `readonly-write` alerts.
- **Implementation:** reads filename/flags from userspace args; bounded-loop
  marker scan; discards uninteresting opens in-kernel (256 KiB ring).

## F3 — Outbound network-connection monitoring
- **Description:** Emits one event per IPv4 `connect()` attempt.
- **Files:** `bpf/netmon.bpf.c`, `netmon_bpf*`, `main.go` `decodeNet`.
- **Dependencies:** `syscalls/sys_enter_connect`, `bpf_probe_read_user`, `bpf_ntohs`.
- **User-facing:** `anomalous-outbound-connection` alerts; `dst` = `ip:port`.
- **Implementation:** reads trimmed `sockaddr_in` from userspace; bails unless
  `AF_INET`; port byte-swapped in-kernel.

## F4 — Unified event pipeline (fan-in)
- **Files:** `main.go` (`readLoop`, `decode*`, `out` channel, consumer).
- **Behavior:** three readers → one `chan Event` → single consumer = sole writer.
- **Implementation:** `binary.Read` LittleEndian into generated structs; `goString`
  NUL-trim; buffered channel (64).

## F5 — YAML rule engine (4 categories)
- **Files:** `rules.go`, `rules.yaml`.
- **Dependencies:** `gopkg.in/yaml.v3`.
- **Behavior:** each category independently toggleable/tunable; produces 0..n
  alerts per event.
- **Implementation:** `evalShellSpawn`/`evalSensitiveFiles`/`evalReadonlyWrites`/
  `evalNetworkAnomaly`, dispatched by `Evaluate` (rules.go:190). See
  [DOMAIN_MODEL](./DOMAIN_MODEL.md).

## F6 — Container-name resolution
- **Files:** `cgroup.go`, `cgroup_test.go`.
- **Dependencies:** cgroup v2 `/sys/fs/cgroup`, `docker inspect`.
- **Behavior:** alerts carry friendly Docker container name; `""` on host;
  `container:<shortid>` fallback.
- **Implementation:** walk cgroupfs to match inode → parse id (both drivers) →
  `docker inspect` (2s timeout) → memoized in `sync.Map`.

## F7 — Alert output: stdout
- **Files:** `main.go` (consumer, `alertJSON`).
- **Behavior:** one JSON alert line per match (RFC3339Nano timestamp, omitempty fields).

## F8 — Alert output: log file (`-log-file`)
- **Files:** `main.go:105`.
- **Behavior:** mirrors all output to an append-mode file via `io.MultiWriter`.

## F9 — Alert output: webhook (`-webhook`)
- **Files:** `webhook.go`, `main.go:84`.
- **Behavior:** Slack-compatible POST per alert; non-blocking enqueue (buffer 100);
  drop-on-full; best-effort no-retry; flushed on shutdown.

## F10 — Verbose raw-telemetry mode (`-verbose`)
- **Files:** `main.go:266`.
- **Behavior:** prints every decoded `Event` in addition to alerts.

## F11 — Dropped-event accounting
- **Files:** `dropped_events` map in each `.bpf.c`; `main.go` (`readDropped`,
  reporter goroutine, shutdown summary).
- **Behavior:** stderr warning every 30s on increase; unconditional per-run total
  at exit.
- **Implementation:** per-CPU array bumped lock-free in-kernel; summed in userspace.

## F12 — Graceful shutdown
- **Files:** `main.go` (signal goroutine, WaitGroup, ordered close).
- **Behavior:** SIGINT/SIGTERM drains all buffered events + queued webhooks before exit.

## F13 — Detection validation suite
- **Files:** `validate/main.go`, `validate/score.go`, `validate/score_test.go`.
- **Dependencies:** Docker, a running traceguard with `-log-file`.
- **Behavior:** runs 7 attacks + 8 benign cases, scores by time-window, prints
  detection % and false-positive %.

## F14 — Performance measurement
- **Files:** `perf_test.sh` (verbose), `perf_steadystate.sh` (alerts-only).
- **Behavior:** measures traceguard CPU% under a 2000×`/bin/true` burst.

## F15 — Containerized distribution
- **Files:** `Dockerfile`, `.github/workflows/ci.yml`.
- **Behavior:** multi-stage build → alpine runtime image; CI pushes to ghcr.io.

## Feature → primary-file matrix
| Feature | eBPF | Go core | Config | Tests |
| --- | --- | --- | --- | --- |
| F1 exec | execmon.bpf.c | main.go | — | (live) |
| F2 file | filemon.bpf.c | main.go | rules.yaml | (live) |
| F3 net | netmon.bpf.c | main.go | rules.yaml | (live) |
| F4 pipeline | — | main.go | — | — |
| F5 rules | — | rules.go | rules.yaml | rules_test.go |
| F6 container | — | cgroup.go | — | cgroup_test.go |
| F7–F10 output | — | main.go, webhook.go | — | webhook_test.go |
| F11 drops | all .bpf.c | main.go | — | — |
| F13 validate | — | validate/ | — | score_test.go |
</content>
