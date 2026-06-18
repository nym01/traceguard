# TraceGuard — Domain & Business Logic

> Source: `rules.go`, `rules.yaml`, `bpf/*.bpf.c`, `cgroup.go`. Rationale:
> `DESIGN.md` §2–§4, `README.md` "Detection rules" / "Known limitations".

## 1. Core domain concepts

| Concept | Meaning in TraceGuard |
| --- | --- |
| **Event** | A normalized record of one kernel observation (an exec, a file open, or a connect). The single currency the whole pipeline speaks. |
| **Monitor** | One eBPF program + ring buffer + reader/decoder that produces one kind of Event. There are three: exec, file, network. |
| **Rule (category)** | One of four detection logics, each with its own typed config section and `eval*` function. Not a generic DSL — four purpose-built evaluators (`DESIGN.md` §4). |
| **Alert** | The structured output produced when a rule matches an event. |
| **Severity** | A free-form label (`critical`/`high`/`medium`/…) attached per rule category in YAML; carried through to output. Not an enum — any string is accepted. |
| **Container attribution** | Mapping an event's kernel cgroup id to a human Docker container name. |
| **Dropped event** | An event the kernel could not enqueue (ring buffer full); counted, never alerted on. |

## 2. The detection model (business rules)

TraceGuard's "business logic" *is* its four detection rules. Each is a pure
function `eval*(Event, <Rule>) *Alert` returning `nil` (no match) or an `*Alert`.

### Rule 1 — `unexpected-shell-spawn` (`evalShellSpawn`, rules.go:89)
**Fires when:** an `exec` event whose `comm` is in `shell_names`, AND whose
`parent_comm` is **not** in `allowed_parents`.
- Default `shell_names`: `sh`, `bash`, `zsh`.
- Default `allowed_parents`: `sh`, `bash`, `sshd`, `systemd`, `login`, `su`, `sudo`, `MainThread`.
- **Why:** the classic reverse-shell / post-exploitation signal — a shell spawned
  by something that has no business spawning one.
- **Hidden assumption / limitation:** parent matching is by **comm name only**. At
  the host level a container's legitimate entrypoint shell and a `docker exec`
  shell into the same container both have parent `containerd-shim` — they are
  indistinguishable (`README.md` known limitation). A real fix needs per-cgroup
  lineage.
- **Race already fixed:** `parent_comm` is captured **in-kernel** at exec time
  (`BPF_CORE_READ_STR_INTO`), not via `/proc/<ppid>/comm` later — the parent may
  have exited by the time userspace looks (`DESIGN.md` §3, commit `73af29f`).

### Rule 2 — `sensitive-file-access` (`evalSensitiveFiles`, rules.go:107)
**Fires when:** a `file_access` event whose `filename` exactly equals one of
`paths`, OR **contains** any of `path_substrings`.
- Default `paths`: `/etc/shadow`, `/etc/gshadow`, `/etc/sudoers`.
- Default `path_substrings`: `.ssh/`, `id_rsa`, `id_ed25519`, `.pem`, `.aws/`.
- **Why:** credential/secret theft. Substrings catch SSH keys and cloud creds
  wherever they live, not just under `/etc/`.
- **Edge case (deliberate):** `/root/.ssh` (directory, no trailing slash) does
  **not** match `.ssh/` — only files inside `.ssh/` do. This is a tested benign
  case (`validate/main.go` `list-ssh-dir`).
- **Edge case:** the open need not succeed — the *attempt* against a matching path
  fires the rule (e.g. reading a nonexistent `/root/.aws/credentials`).
- **Cross-layer dependency:** for a *read* of a credential file outside `/etc/` to
  reach this evaluator, the kernel filter (`has_sensitive_marker` in
  `filemon.bpf.c`) must forward it. The two must stay in sync — see [Risks](./CODE_QUALITY_REVIEW.md). A past bug (`fc29078`) was exactly this layering gap.

### Rule 3 — `readonly-write` (`evalReadonlyWrites`, rules.go:135)
**Fires when:** a `file_access` event whose `flags` include any write-ish bit
(`O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND`) AND whose `filename` has a prefix in
`protected_prefixes`.
- Default `protected_prefixes`: `/usr/`, `/bin/`, `/sbin/`, `/lib/`, `/etc/`.
- **Why:** tampering / persistence (writing binaries or config that should be
  immutable at runtime).
- **Dual-use by design:** legitimate package managers writing under `/usr/` will
  trip this; a real deployment allowlists them by comm name. Same tradeoff Falco's
  default ruleset accepts (`README.md`).

### Rule 4 — `anomalous-outbound-connection` (`evalNetworkAnomaly`, rules.go:165)
**Fires when:** a `network` event whose `dst_port` is **not** in `allowed_ports`.
- Default `allowed_ports`: `80`, `443`, `53`, `22`.
- **Why:** reverse-shell callback, C2 beaconing, exfiltration.
- **Limitation:** IPv4 only (`netmon.bpf.c` bails unless `sin_family == AF_INET`).
  Fires on every connect *attempt*, including refused ones (probing a dead C2 is
  still relevant).

## 3. Domain rules & constraints (cross-cutting)

- **Multiple alerts per event are allowed.** `Evaluate` runs all four evaluators
  and appends every non-nil result (rules.go:190). Usually 0–1, but a single
  `file_access` could match both `sensitive-file-access` and `readonly-write`.
- **Disabled rule = silent.** Each `eval*` first checks `r.Enabled`; a disabled
  category never fires.
- **Type gating.** Each evaluator early-returns unless `e.Type` matches its domain
  (`exec` / `file_access` / `network`), so a network event can never trip a file
  rule.
- **No correlation / no state.** Each event is judged in isolation. A credential
  read followed by an outbound connect from the same PID is two independent
  alerts, not one attack-chain alert (explicit v1 non-goal).
- **Severity is advisory.** It is copied from config into the alert; nothing in
  the engine treats `critical` differently from `medium`. (`Severity` is a
  `string` typedef, not a validated enum.)

## 4. Kernel-side business logic (the in-kernel filter)

The kernel is a **coarse pre-filter**, never the policy authority (`DESIGN.md` §2):

- `filemon` forwards an open to userspace **only if**: it's a write (any path), OR
  the path begins with literal `/etc/`, OR `has_sensitive_marker` matches a
  credential marker (`.ssh/`, `.aws/`, `.pem`, `id_rsa`, `id_ed25519`).
  Everything else is `bpf_ringbuf_discard`ed in-kernel to protect signal/throughput.
- `netmon` forwards only `AF_INET` connects.
- `execmon` forwards every successful exec (low volume; no filter).

**Invariant:** the kernel filter must never drop anything the rule engine *would*
match. The marker list in `has_sensitive_marker` is therefore a superset-ish
mirror of `sensitive_files.path_substrings`. Drift here = silent missed detections.

## 5. Container attribution logic (`cgroup.go`)

- `bpf_get_current_cgroup_id()` returns, on cgroup v2, the **inode** of a
  directory under `/sys/fs/cgroup`. There is no syscall to reverse it, so
  `findCgroupPath` **walks the tree and stats each dir** until an inode matches.
- `containerIDFromCgroupPath` recognizes both Docker cgroup drivers:
  - cgroupfs: `.../docker/<64-hex-id>`
  - systemd: `.../docker-<64-hex-id>.scope`
  - Requires a full **64-char hex** id (`isHexID`) to avoid false matches.
- The id is resolved to a friendly name via `docker inspect --format {{.Name}}`
  (2s timeout). On any failure (no docker, gone container, timeout) it returns
  `container:<12-char-shortid>` — degraded but still useful.
- Non-container cgroups (host root, systemd services, user slices) resolve to `""`
  and the `container` field is omitted from output.

## 6. Domain assumptions baked into code
1. **cgroup v2** semantics (cgroup id == directory inode). cgroup v1 hosts will
   not resolve names correctly.
2. **Docker** is the container runtime (paths and `docker inspect`). containerd/
   CRI-O/podman names are not resolved.
3. **x86_64** syscall/flag conventions (hand-defined `O_*` bits in `filemon.bpf.c`
   match asm-generic; build cflags target `x86_64-linux-gnu`).
4. **Kernel ≥ 5.3** (bounded-loop verifier) with **BTF** available.
5. **glibc routes opens through `openat`** — legacy `open()` is uncovered.
</content>
