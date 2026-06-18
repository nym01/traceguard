# TraceGuard — Development Guide

> Source: `README.md`, `Dockerfile`, `.github/workflows/ci.yml`, `go.mod`,
> `main.go` (`//go:generate` directives), perf/validate scripts.

## 1. Prerequisites

| Tool | Why | Notes |
| --- | --- | --- |
| Go ≥ 1.26 | builds the userspace binary | `go.mod` declares `go 1.26.4` |
| Linux kernel ≥ 5.3 with **BTF** | run the eBPF programs | `/sys/kernel/btf/vmlinux` must exist |
| root / `CAP_BPF`+`CAP_SYS_ADMIN` | load eBPF + attach tracepoints | needed only to **run**, not to build |
| clang + llvm + libbpf-dev | compile `bpf/*.bpf.c` via bpf2go | needed only to **regenerate** eBPF objects |
| Docker | container-name resolution + validation suite | optional for core run |

> **You do not need clang to build.** The bpf2go-generated `.go`/`.o` artifacts
> are committed, so `go build` works on a clean machine. Reinstall clang only to
> re-run `go generate` after editing a `.bpf.c` file.

## 2. Local setup & build

```sh
git clone <repo> && cd traceguard

# (only if you changed a bpf/*.bpf.c source — needs clang/libbpf-dev)
go generate ./...

go build -o traceguard .          # produces ./traceguard
```

The `//go:generate` directives (main.go:37–39) invoke bpf2go with
`-cflags "-O2 -g -Wall -Werror -I/usr/include/x86_64-linux-gnu" -type event`
for each `bpf/*.bpf.c`, producing `<name>_bpf{el,eb}.{go,o}`.

## 3. Running

```sh
sudo ./traceguard                                  # alerts-only, stdout
sudo ./traceguard -verbose                         # also dump raw event stream
sudo ./traceguard -rules ./rules.yaml -log-file traceguard.log
sudo ./traceguard -webhook https://hooks.slack.com/services/XXX/YYY/ZZZ
```

### Docker
```sh
docker build -t traceguard .
docker run --rm --privileged \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  -v /sys/kernel/debug:/sys/kernel/debug:rw \
  traceguard
```
- `--privileged` → `CAP_BPF`/`CAP_SYS_ADMIN` for eBPF load (narrow to those caps
  in hardened deployments).
- `/sys/kernel/btf` (ro) → CO-RE relocation against the host kernel BTF.
- `/sys/kernel/debug` (rw) → tracepoint attach via `perf_event_open` (tracefs).

> For container-name resolution inside Docker you'd additionally need the host
> `/sys/fs/cgroup` and the docker socket/CLI available — not wired in the default
> run command. (Assumption: container-name resolution is primarily a bare-host
> feature today.)

## 4. Testing

```sh
go vet ./...
go test ./...            # pure-Go unit tests (rules, webhook, cgroup, validate scorer)
go test -v ./...         # verbose, as CI runs it
```
Unit tests **do not** load eBPF or touch the real kernel/docker:
- `rules_test.go` `TestMain` points `cgroupRoot` at a temp dir so resolution
  returns `""` without walking the real `/sys/fs/cgroup`.
- `cgroup_test.go` `TestFindCgroupPath` builds a fake tree in `t.TempDir()`.

### Detection validation (needs root + Docker + a live kernel)
```sh
# Terminal 1
sudo ./traceguard -log-file validation.log
# Terminal 2
go build -o traceguard-validate ./validate
./traceguard-validate -log validation.log     # -log MUST match -log-file
```
Prints a per-case PASS/FAIL table plus detection-rate / false-positive-rate.

### Performance
```sh
# verbose mode
sudo ./traceguard -verbose -log-file perf.log     # terminal 1
./perf_test.sh perf.log                            # terminal 2
# steady-state (alerts-only)
sudo ./traceguard -log-file perf_steadystate.log   # terminal 1
./perf_steadystate.sh                              # terminal 2
```

## 5. Common developer tasks

| Task | How |
| --- | --- |
| **Tune a rule** | Edit `rules.yaml` (lists/severity/enabled), restart. No rebuild. |
| **Add a value to an allowlist/markerset** | Edit `rules.yaml`; **if it's a credential read marker, also update `has_sensitive_marker` in `filemon.bpf.c`** + `go generate` (kernel filter must forward what the rule would match). |
| **Add a new rule category** | Add struct + YAML section in `rules.go`/`rules.yaml`, write `evalX`, add it to the `Evaluate` slice (rules.go:192). |
| **Add a new monitor** | New `bpf/X.bpf.c` (+ `//go:generate` line) → `go generate` → in `run()` repeat load/attach/reader → add `decodeX` → add to `dropMonitors`, `wg.Add`, a reader goroutine. |
| **Change an event field** | Edit the C `struct event`, `go generate`, update the matching `decodeX` and `Event`/`alertJSON`. Keep C/Go layouts in sync. |
| **Regenerate eBPF objects** | `go generate ./...` (needs clang/libbpf-dev). |

## 6. Debugging

- **Run with `-verbose`** to see the raw event stream and confirm the kernel is
  delivering what you expect before blaming the rules.
- **eBPF load/verifier errors** surface from `loadXObjects` at startup
  (`load execmon objects: ...`). The verifier log is the key artifact — common
  traps: stack > 512 bytes, unbounded loops, out-of-bounds array access (mask
  indices with `& 0xff`; see `DESIGN.md` §2 on the `#pragma unroll` trap).
- **Dropped events** in stderr warnings mean the ring buffer is full — raise
  `max_entries` in the relevant `.bpf.c` or reduce event volume.
- **Missing container names**: check cgroup v2, that the docker CLI is on PATH,
  and that the cgroup id actually corresponds to a Docker cgroup (`isHexID`
  requires a full 64-hex id).
- **A rule that "should" fire doesn't**: check whether the **kernel filter**
  dropped the event first (relevant for credential *reads* — see `DESIGN.md` §3
  bug `fc29078`).

## 7. Build process & release

- **CI** (`.github/workflows/ci.yml`): on push/PR/release —
  `setup-go 1.26` → install clang/llvm/libbpf-dev → `go generate` → `go vet` →
  `go test -v` → `go build`. eBPF is **not loaded** in CI (runner kernel/BTF not
  guaranteed); live load is verified locally only.
- **Release / image push**: the `docker` job runs only on push to `main` or a
  published release; builds the multi-stage image and pushes
  `ghcr.io/<repo>:latest` and `:<sha>` (auth via `GITHUB_TOKEN`).
- **Versioning**: no semantic version tags observed in-repo; images are tagged by
  `latest` and commit SHA. (Assumption: releases drive tagged images via the
  `release: published` trigger.)

## 8. Coding conventions
- Standard `gofmt`/`go vet`-clean Go; tabs; descriptive doc comments on exported
  and most unexported funcs.
- **C and Go `struct event` layouts must match** — comments in each `.bpf.c` say
  so explicitly.
- Generated `*_bpf*.go`/`.o` are **committed and never hand-edited**.
- Errors are wrapped with `%w` and context; startup failures are fatal and loud.
- Tests are table-driven where it helps (`cgroup_test.go`, `validate/score_test.go`).
</content>
