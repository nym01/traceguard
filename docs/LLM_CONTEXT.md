# TraceGuard — LLM Context Package

> Load **this file alone** to become productive on TraceGuard. Deeper detail lives
> in the sibling docs, but everything essential is here.

## What it is
TraceGuard is a **detect-only Linux runtime security agent** (a small Falco-like
tripwire). Three eBPF programs watch process execs, file opens, and outbound
connects at the kernel level; one Go binary normalizes those into a unified
`Event`, runs each through a YAML rule engine, and emits JSON alerts to
stdout / a log file / a webhook. **No DB, no server, no frontend, no auth.** Single
long-running root daemon, one per host. v1 detects and reports; it does **not**
block (enforcement is a deferred v2).

## Architecture in one breath
`tracepoint → eBPF prog → per-monitor RINGBUF → reader goroutine (decode) →
shared chan Event (buf 64) → single consumer goroutine = sole stdout writer →
Evaluate(event, rules) → alert JSON (+ optional log file + webhook)`.
Three monitors, **one identical pipeline pattern**. The consumer is the only
writer to stdout (guarantees atomic JSON lines).

## Critical files (read these first)
| File | What it is | Why it matters |
| --- | --- | --- |
| `main.go` | pipeline lifecycle: flags, load/attach 3 eBPF progs, goroutines, decoders, shutdown | the spine; `run()` is the whole program |
| `rules.go` | `Event`, `RuleConfig`, `Alert`, 4 `eval*`, `Evaluate` | all detection logic |
| `rules.yaml` | rule config (4 categories) | tune detection without rebuild |
| `bpf/execmon.bpf.c` | exec monitor | captures pid/ppid/comm/parent_comm/filename in-kernel |
| `bpf/filemon.bpf.c` | file monitor + **in-kernel noise filter** (`has_sensitive_marker`) | high-volume; coarse-filters in kernel |
| `bpf/netmon.bpf.c` | IPv4 connect monitor | reads `sockaddr_in` from userspace arg |
| `cgroup.go` | cgroup id → Docker container name | runs inside `Evaluate` on the consumer goroutine |
| `webhook.go` | Slack-compatible POST sender | non-blocking, best-effort |
| `validate/` | attack/benign suite + time-window scorer | how detection quality is measured |
| `*_bpf{el,eb}.go/.o` | **bpf2go-generated, committed, never hand-edit** | lets `go build` work without clang |

## Repository tree (annotated)
```
main.go                  pipeline + lifecycle (run())
rules.go / rules.yaml    rule engine + config
cgroup.go                container-name resolution (memoized)
webhook.go               optional webhook sender
bpf/execmon.bpf.c        exec eBPF program
bpf/filemon.bpf.c        file eBPF program (+ noise filter)
bpf/netmon.bpf.c         network eBPF program
*_bpfel.go *_bpfeb.go    bpf2go Go bindings (LE/BE)  — generated
*_bpfel.o  *_bpfeb.o     compiled eBPF objects        — generated
*_test.go                unit tests (rules, webhook, cgroup)
validate/                detection validation harness
perf_test.sh             CPU overhead, verbose mode
perf_steadystate.sh      CPU overhead, alerts-only mode
Dockerfile               multi-stage build → alpine
.github/workflows/ci.yml CI: vet/test/build + push image to ghcr.io
README.md / DESIGN.md    what & how / why (read DESIGN for rationale)
```

## Core workflows
1. **Event hot path:** kernel fills `struct event` → ring buffer → `readLoop` →
   `decodeX` → `Event` → consumer → `Evaluate` → print alert (+webhook).
2. **Rule eval:** `Evaluate` runs all 4 `eval*`; each gates on `Enabled` +
   `e.Type`; returns 0..n alerts (multiple matches allowed).
3. **Container resolution:** walk `/sys/fs/cgroup` to match inode → parse Docker
   id → `docker inspect` (2s timeout) → cache. Failures degrade to `""` or
   `container:<shortid>`, never error.
4. **Shutdown:** signal → close readers + reporterStop → `wg.Wait()` (4 goroutines)
   → `close(out)` → printer drains → drop summary → flush+close webhook.

## Important business rules
- 4 rule categories: `unexpected-shell-spawn`, `sensitive-file-access`,
  `readonly-write`, `anomalous-outbound-connection`. Defaults in `rules.yaml`.
- Shell-spawn parent matching is **comm-name only** → can't tell a container's
  entrypoint shell from a `docker exec` shell (both parent `containerd-shim`).
- `readonly-write` fires on any write-flag open under `/usr//bin//sbin//lib//etc/`
  — dual-use (package managers trip it).
- Network rule: IPv4 only, fires on any connect to a port outside `allowed_ports`.
- Severity is advisory (a free-form string), not semantically enforced.
- No cross-event correlation (each event judged alone).

## Coding conventions
- `gofmt`/`go vet` clean; doc comments on most funcs.
- **C `struct event` ↔ Go decoder layouts must stay byte-aligned** (`binary.Read`
  is positional — no compile-time check).
- **`rules.yaml` `path_substrings` ↔ `has_sensitive_marker` in `filemon.bpf.c`
  must stay in sync** for credential *reads* outside `/etc/`.
- Generated `*_bpf*` files are committed and never hand-edited — change the
  `.bpf.c` and `go generate`.
- Errors wrapped with `%w`; startup errors are fatal and loud.

## Known pitfalls (where edits silently break things)
1. **Struct layout drift** (C↔Go) → corrupted fields, no error. Add decoder
   round-trip tests.
2. **Kernel-filter / rule-substring drift** → silent missed detections (this was a
   real shipped bug, `fc29078`).
3. **Blocking in `cgroup.go`** → it runs on the consumer goroutine; a slow
   `docker inspect` stalls **all** alert output.
4. **WaitGroup count** must equal goroutines (3 readers + 1 reporter); wrong count
   → deadlock or lost final events; closing `out` before readers exit → panic.
5. **Second writer to stdout** → interleaved JSON lines.
6. **Changing alert JSON** → breaks the `validate/` scorer and any SIEM consumer.

## Areas requiring caution
- Anything touching `bpf/*.bpf.c`: re-`go generate` (needs clang/libbpf-dev), mind
  the BPF verifier (512-byte stack, bounded loops not `#pragma unroll`, mask array
  indices `& 0xff` — see `DESIGN.md` §2).
- `cgroup.go` performance on container-dense hosts (unbounded cache, full-tree
  walk per new cgroup, shell-out per new container).
- Runs as **root/privileged** — treat alert contents (cred paths, C2 IPs) and the
  `0644` log file as sensitive.

## How to run / test (fast reference)
```sh
go build -o traceguard . && sudo ./traceguard            # run (root needed)
sudo ./traceguard -verbose -log-file tg.log              # see raw events
go test ./...                                             # unit tests (no kernel/docker)
go generate ./...                                         # regen eBPF (needs clang)
# validation: run traceguard -log-file X, then: go run ./validate -log X
```

## Dependencies (minimal by design)
| Dep | Purpose | Replaceable by |
| --- | --- | --- |
| `github.com/cilium/ebpf` v0.21.0 | load/attach eBPF, ring buffers, bpf2go | libbpfgo (heavier, cgo) |
| `gopkg.in/yaml.v3` v3.0.1 | parse `rules.yaml` | any YAML lib / switch to JSON |
| `golang.org/x/sys` (indirect) | syscall constants | — |
| clang/llvm/libbpf-dev (build-time) | compile `.bpf.c` | none (required for eBPF) |
| Docker (runtime, optional) | container-name resolution + validation | containerd/CRI APIs (not implemented) |

**Technical-debt risk:** cilium/ebpf is the single load-bearing dependency; an
API break there touches `main.go` + all generated bindings. Otherwise the
dependency surface is tiny and low-risk.

## Future contributor guide (principles to preserve)
- **Keep the kernel a coarse filter; keep policy in the rule engine.** Widen the
  kernel net only enough to never drop what a rule would match.
- **Keep one consumer = one writer.** Never add a second stdout writer.
- **Keep monitors uniform.** A new signal should be "another reader goroutine,"
  not a new pipeline shape.
- **Keep detection honest.** Add evasion + near-miss benign cases to `validate/`
  when adding a rule; the suite's value is its adversarial composition.
- **Prefer typed rule sections over a DSL** until v1's four categories genuinely
  don't fit (`DESIGN.md` §4).
- To debug production: run `-verbose` to confirm raw events; check drop counters;
  for a "missing" file alert, suspect the kernel filter first.
</content>
