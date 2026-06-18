# TraceGuard — Code Quality, Risks & Testing Review

> Evidence-based assessment from reading the source. Citations use
> `file:line`. See [CHANGE_IMPACT_MAP](./CHANGE_IMPACT_MAP.md) for blast radius.

## 1. Architectural strengths

1. **One pipeline pattern, three monitors** — uniform load→attach→ring→decode→
   channel shape (`main.go`, `DESIGN.md` §1) makes the code easy to read and
   extend; adding a monitor is mechanical.
2. **Single-writer output discipline** — one consumer owns stdout (main.go:264),
   eliminating interleaved-line races by construction.
3. **Clean kernel/userspace division of labor** — kernel is a *coarse* filter,
   userspace makes precise decisions (`DESIGN.md` §2). Keeps eBPF programs simple
   and verifier-friendly.
4. **Lossy-but-never-blocking backpressure** — per-CPU drop counters + non-blocking
   webhook enqueue (`webhook.go:64`) ensure the monitored host is never stalled.
5. **Race fixed at the right layer** — parent comm captured in-kernel, not via
   `/proc` (`execmon.bpf.c:87`, `DESIGN.md` §3) — the fix removes the race rather
   than masking it.
6. **CO-RE without `vmlinux.h`** — hand-declared partial structs keep the build
   self-contained (`DESIGN.md` §2).
7. **Genuinely thoughtful tests & validation** — the suite is built to avoid
   measuring its own artifacts (`validate/main.go` comments), and unit tests stub
   the filesystem (`rules_test.go` TestMain).
8. **Excellent documentation** — `README.md` + `DESIGN.md` are unusually candid
   about limitations and rationale.

## 2. Weaknesses, smells & technical debt

| # | Issue | Evidence | Severity |
| --- | --- | --- | --- |
| W1 | **Cross-layer coupling: kernel marker list vs rule substrings must stay in sync.** A credential marker added to `rules.yaml` but not to `has_sensitive_marker` is silently undetected (the original `fc29078` bug class). | `filemon.bpf.c:82` vs `rules.yaml` `path_substrings` | High |
| W2 | **`findCgroupPath` walks the entire cgroup tree on every cache miss.** A `filepath.WalkDir` + `stat` per directory; on a busy host with many short-lived containers, new cgroup ids each cause a full walk. Cached after, but cold cost scales with cgroup count. | `cgroup.go:83` | Medium |
| W3 | **`docker inspect` shell-out per new cgroup.** Process spawn on the alert path (off the hot consumer? no — it's called *inside* `Evaluate` on the consumer goroutine). A 2s-timeout `docker` exec on the sole stdout writer can stall all alert printing. | `cgroup.go:65`, `rules.go:102` | High |
| W4 | **`containerNameCache` never evicts.** Unbounded `sync.Map` keyed by cgroup id; long-lived hosts churning containers leak entries. | `cgroup.go:35` | Medium |
| W5 | **No rule-config validation.** Unknown YAML keys, typo'd severities, or an empty `shell_names` are accepted silently; a mis-typed section just disables a rule. | `main.go:44` `loadRules` | Medium |
| W6 | **In-kernel `/etc/` and credential matching are byte-prefix / substring scans** — relative-path opens against an `/etc` dirfd bypass the `/etc/` fast-path (documented). | `filemon.bpf.c:139`, `README.md` limitations | Low (known) |
| W7 | **`Severity` is an unvalidated string typedef**, not an enum; nothing consumes it semantically. | `rules.go:9` | Low |
| W8 | **No config hot-reload** — rule changes require a restart (drops in-flight ring state). | `main.go:73` | Low |
| W9 | **Webhook URL passed via argv** — visible in process listing; a Slack URL is a secret. | `main.go:66` | Medium (sec) |
| W10 | **`true_count` grep in `perf_test.sh` is heuristic** (string match on JSON) — brittle if output format changes. | `perf_test.sh:65` | Low |

## 3. Security concerns

- **Runs as root / privileged** — by necessity (eBPF). Standard EDR risk; minimize
  blast radius with `CAP_BPF`+`CAP_SYS_ADMIN` instead of `--privileged` (README
  notes this).
- **Webhook over plaintext `http`** is allowed (warned, not blocked) — alert
  contents (paths, IPs, comms) leak unencrypted (main.go:95).
- **Alert contents are sensitive** — they describe credential file paths and C2
  IPs; the log file is `0644` (world-readable). Consider `0600`.
- **`docker inspect` is invoked with an attacker-influenced id?** No — the id comes
  from a stat'd cgroup path validated as 64-hex (`isHexID`), so no shell injection
  surface (it's `exec.CommandContext`, not a shell). Good.
- **No authentication on output** — anyone who can read stdout/log/webhook sees
  alerts. Acceptable for a host agent; note for shared environments.

## 4. Scalability concerns
- **Single-host only**, no aggregation tier (explicit v1 boundary).
- **Ring buffer sizing is static**; file/net at 256 KiB may drop under heavy load
  (drop counters will show it).
- **Container resolution cost** (W2/W3) is the main per-event scalability risk on
  container-dense hosts.

## 5. Maintainability concerns
- The **C↔Go struct sync** and **kernel-filter↔rule sync** (W1) are the two places
  a well-meaning edit silently breaks detection. Both are comment-documented but
  not enforced by a test.
- Generated files are committed — convenient, but a reviewer must remember to
  regenerate after a `.bpf.c` change (CI does `go generate`, which guards drift).

## 6. Testing analysis

### Existing tests (all pure-Go, no kernel/docker)
| File | Covers |
| --- | --- |
| `rules_test.go` | All four evaluators: fire + don't-fire paths (shell parent allow/deny, sensitive exact + substring, readonly write-flag vs read-only, network allowed vs unexpected port). |
| `webhook_test.go` | Payload shape, nil-channel no-op, full-channel drop-without-block, 500 status, unreachable URL, marshal error. |
| `cgroup_test.go` | `containerIDFromCgroupPath` (both drivers + negatives), `shortID`, `trimContainerName`, no-match resolution, `findCgroupPath` against a fake temp tree. |
| `validate/score_test.go` | `loadAlerts` filtering, attack/benign scoring, window boundaries, rate math, divide-by-zero guard. |

### Coverage map
| Area | Tested? |
| --- | --- |
| Rule logic | ✅ strong |
| Webhook sender | ✅ strong |
| Container path parsing/resolution | ✅ good (logic), ❌ `docker inspect` path not exercised |
| Validation scorer | ✅ strong |
| **eBPF programs** | ❌ none (only verified by live local runs + validation suite) |
| **Decoders (`decodeExec/File/Net`)** | ❌ none (no round-trip byte test) |
| **`run()` lifecycle / shutdown ordering** | ❌ none |
| **`loadRules` error paths** | ❌ none |

### Recommended additional tests
1. **Decoder round-trip tests**: marshal a known `*_bpfEvent` to bytes, run
   `decodeX`, assert the resulting `Event` — catches C↔Go layout drift cheaply.
2. **Kernel-filter ↔ rule-substring consistency test** (W1): assert every
   `sensitive_files.path_substrings` entry has a corresponding marker in a
   parsed/representative list (or document the canonical source).
3. **`loadRules`**: malformed YAML, missing file, empty sections.
4. **Integration smoke test** behind a build tag that requires root, attaches the
   programs, execs `/bin/true`, and asserts an event flows (CI can skip it).
5. **Severity enum validation** + a warning for unknown YAML keys.

## 7. Overall verdict
A **well-architected, well-documented, single-author v1** with high craft in the
hot path and honest limitation tracking. The principal latent risks are
operational, not logical: the **`docker inspect` shell-out on the consumer
goroutine** (W3) and the **kernel-filter/rule sync coupling** (W1). Both are
addressable without architectural change.
</content>
