# TraceGuard — Change Impact Map

> "If a developer modifies X → what's affected, what may break, what to test, what
> depends on it." Use alongside [CODE_QUALITY_REVIEW](./CODE_QUALITY_REVIEW.md)
> risks (W1–W10).

## Legend
- **Affects** = files/areas you must also touch or recheck.
- **Breaks** = the failure mode if you get it wrong.
- **Test** = what to run.

---

## 1. Modify a `struct event` in any `bpf/*.bpf.c`
- **Affects:** that program's bpf2go output (must `go generate`), the matching
  `decodeExec/File/Net` (main.go:399–445), `Event` (rules.go:13), possibly
  `alertJSON` (main.go:334).
- **Breaks:** silent **field misalignment** — `binary.Read` reads bytes
  positionally; a wrong order/size corrupts every field after it. No compile error.
- **Test:** add/​run a **decoder round-trip test** (recommended in review §6.3);
  `go test ./...`; live run with `-verbose` to eyeball fields.
- **Depends on it:** the entire pipeline downstream of decode.

## 2. Add/remove a credential marker in `rules.yaml` `path_substrings`
- **Affects:** **`has_sensitive_marker` in `filemon.bpf.c:82`** (the kernel filter
  must forward what the rule would match) → `go generate`, rebuild.
- **Breaks:** **silent missed detection** for *reads* outside `/etc/` if you update
  the rule but not the kernel filter (this is exactly bug `fc29078`).
- **Test:** `rules_test.go` for the rule; live validation case for the read path;
  ideally the consistency test recommended in review §6.2.
- **Depends on it:** `sensitive-file-access` detection completeness (W1).

## 3. Tune a rule list (allowed_parents, allowed_ports, protected_prefixes, shell_names)
- **Affects:** `rules.yaml` only (no rebuild; restart to reload).
- **Breaks:** false negatives (over-broad allowlist) or false positives
  (under-broad). `protected_prefixes`/`/usr/` is dual-use — adding package managers
  to an allowlist isn't supported by comm today, so be careful.
- **Test:** `go test ./...` (rule logic unchanged), then `validate/` suite.
- **Depends on it:** alert volume / signal quality.

## 4. Add a new rule category
- **Affects:** new struct + field in `RuleConfig` (rules.go:33), new YAML section
  (rules.yaml), new `evalX`, add to the `Evaluate` slice (rules.go:192).
- **Breaks:** if you forget to add it to `Evaluate`, the rule silently never runs.
- **Test:** new unit tests mirroring `rules_test.go`; add a `validate/` case.
- **Depends on it:** nothing downstream needs changes (alert shape is generic).

## 5. Add a new monitor (4th signal)
- **Affects:** new `bpf/X.bpf.c` + `//go:generate` line (main.go:37) → `go generate`;
  in `run()`: load/attach/reader block, a `decodeX`, an entry in `dropMonitors`
  (main.go:206), `wg.Add` count, a reader goroutine, possibly new `Event` fields.
- **Breaks:** WaitGroup count mismatch → premature `close(out)` or hang;
  forgotten drop-monitor entry → no drop accounting for the new signal.
- **Test:** decoder test; live run; validation case.
- **Depends on it:** the consumer/rule engine need no change (that's the design win).

## 6. Change ring buffer `max_entries` in a `.bpf.c`
- **Affects:** that program only → `go generate`, rebuild.
- **Breaks:** too small → more drops under load; too large → memory (16 MiB exec is
  already large).
- **Test:** `perf_test.sh` under burst; watch drop counters.

## 7. Modify `cgroup.go` (container resolution)
- **Affects:** `Alert.Container` values; performance of the **consumer goroutine**
  (resolution runs inside `Evaluate`).
- **Breaks:** a slow/blocking change here **stalls all alert output** (sole stdout
  writer). Cache key/logic bugs → wrong or missing container names.
- **Test:** `cgroup_test.go`; live run against real Docker containers.
- **Depends on it:** every alert's `container` field; W2/W3/W4 risks live here.

## 8. Modify the consumer goroutine (main.go:264)
- **Affects:** stdout/log output, webhook mirroring, verbose printing.
- **Breaks:** introduce a second writer → interleaved JSON lines; block here →
  back-pressure the `out` channel → eventually ring drops.
- **Test:** `go test ./...` (indirect), live run; verify line atomicity.

## 9. Modify shutdown ordering / WaitGroup (main.go:215, 302–326)
- **Affects:** clean drain of events and webhook flush.
- **Breaks:** wrong `wg.Add` count → deadlock or lost final events; closing `out`
  before readers exit → send-on-closed-channel panic; closing webhook channel early
  → dropped queued alerts.
- **Test:** run, Ctrl-C under load, confirm drop summary prints and no panic.

## 10. Change the alert JSON shape (`alertJSON` / `webhookPayload`)
- **Affects:** **external consumers**: the `validate/` scorer keys off
  `type:"alert"` + `timestamp` + `rule` (score.go:15); any downstream SIEM/Slack
  integration; `perf_test.sh`'s grep heuristic (perf_test.sh:65).
- **Breaks:** validation suite mis-scores; downstream parsers fail.
- **Test:** `validate/score_test.go`; re-run the validation suite end-to-end.

## 11. Modify CI / Dockerfile
- **Affects:** build reproducibility, image push to ghcr.io.
- **Breaks:** Go/clang version drift (must match `go.mod` 1.26.4); missing
  libbpf-dev breaks `go generate`.
- **Test:** local `docker build`; push gated to main/release only.

## Cross-cutting "danger zones" (highest blast radius)
| Zone | Why dangerous |
| --- | --- |
| C↔Go struct layout (item 1) | silent data corruption, no compile error |
| kernel marker ↔ rule substrings (item 2) | silent missed detections |
| consumer goroutine single-writer (items 7,8) | output corruption / pipeline stall |
| WaitGroup/shutdown (item 9) | panic / deadlock / lost events |
| alert JSON contract (item 10) | breaks every external consumer |
</content>
