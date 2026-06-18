# TraceGuard — API & Interface Reference

> TraceGuard exposes **no inbound network API** (no HTTP server, no RPC). Its
> "API surface" is: (1) the **CLI flags**, (2) the **stdout/log JSON output
> contract**, and (3) the single **outbound webhook POST**. Source: `main.go`,
> `webhook.go`.

## 1. Command-line interface

```
traceguard [-rules PATH] [-verbose] [-log-file PATH] [-webhook URL]
```

| Flag | Type | Default | Required | Purpose |
| --- | --- | --- | --- | --- |
| `-rules` | string | `rules.yaml` | no | Path to YAML rule-config file. **Fatal** if missing/unparseable (fail-fast: nothing to detect against). |
| `-verbose` | bool | `false` | no | Also print the raw telemetry stream (every Event), not just alerts. |
| `-log-file` | string | _(off)_ | no | Append all output to this file *in addition to* stdout (`io.MultiWriter`). **Fatal** if the path can't be opened. |
| `-webhook` | string | _(off)_ | no | POST each alert as JSON to this URL. **Fatal** at startup if URL is unparseable or scheme isn't `http`/`https`. Warns on stderr if plaintext `http`. |

**Runtime requirement:** must run as root or with `CAP_BPF`/`CAP_SYS_ADMIN` (+
debugfs) — enforced by the kernel at eBPF load; otherwise `run()` returns an
error like `load execmon objects: ...` and exits non-zero.

**Exit codes:** `0` on clean shutdown (SIGINT/SIGTERM); `1` on any startup/runtime
error (`main()` prints `traceguard: <err>` to stderr and `os.Exit(1)`).

## 2. Output contract — stdout / `-log-file`

One **JSON object per line** (newline-delimited JSON). Two shapes:

### 2.1 Alert line (emitted in all modes when a rule matches)
```json
{
  "type": "alert",
  "timestamp": "2026-06-18T12:34:56.789012345Z",
  "rule": "unexpected-shell-spawn",
  "severity": "high",
  "message": "shell \"bash\" spawned by unexpected parent \"containerd-shim\" (ppid 4321)",
  "pid": 12345,
  "cgroup_id": 91234,
  "container": "payment-service",
  "comm": "bash",
  "filename": "/usr/bin/evil",
  "dst": "45.33.32.156:4444"
}
```
- `type` is always `"alert"`. `timestamp` is RFC3339Nano wall-clock at print time.
- `cgroup_id`, `container`, `filename`, `dst` are **omitted when empty** — e.g. an
  exec alert carries no `dst`; a host (non-container) alert carries no `container`.

### 2.2 Raw event line (only with `-verbose`)
The unified `Event` marshaled directly (no `type:"alert"`; `type` is
`exec`/`file_access`/`network`):
```json
{"type":"exec","pid":12345,"ppid":4321,"cgroup_id":91234,"comm":"bash","parent_comm":"sshd","filename":"/usr/bin/bash"}
```
Consumers distinguishing the two should key off `type` (`"alert"` vs the event
types). The validation scorer (`validate/score.go`) does exactly this.

### 2.3 stderr (operational, not part of the data contract)
- Startup banner: `traceguard: monitoring process execs, file access, and network connections (Ctrl-C to stop)`.
- Drop warnings every 30s: `... dropped N <monitor> events in the last 30s (ring buffer full)`.
- Per-run drop summary at exit (printed unconditionally, even if zero).
- Errors (read/decode/marshal/webhook failures).

## 3. Outbound webhook POST (`webhook.go`)

When `-webhook URL` is set, each alert is POSTed once.

| Property | Value |
| --- | --- |
| Method | `POST` |
| URL | the `-webhook` value |
| `Content-Type` | `application/json` |
| Body | `webhookPayload` (below) |
| Client timeout | 5 seconds |
| Retries | **none** — failures are logged to stderr, not retried |
| Success criterion | response status `< 300`; `>= 300` logs `unexpected status N` |

**Request body:**
```json
{
  "text": "[high] unexpected-shell-spawn: shell \"bash\" spawned by unexpected parent \"containerd-shim\" (ppid 4321)",
  "alert": {
    "rule": "unexpected-shell-spawn",
    "severity": "high",
    "message": "...",
    "pid": 12345,
    "cgroup_id": 91234,
    "container": "payment-service",
    "comm": "bash"
  }
}
```
`text` is what Slack incoming webhooks render; `alert` is the full structured
`Alert` for generic receivers.

**Delivery semantics (at-most-once, best-effort):**
- Alerts are enqueued non-blocking onto a **100-deep** channel. If full, the alert
  is **dropped** with `traceguard: webhook: queue full, dropping alert` — detection
  is never blocked on the network.
- On shutdown the channel is closed and drained (`webhookWG.Wait()`), so queued
  alerts flush before exit.
- A single sender goroutine; alerts are sent **in order**, one at a time.

## 4. OpenAPI-style sketch (outbound webhook)

```yaml
openapi: 3.0.3
info: { title: TraceGuard Webhook (outbound), version: "1.0" }
paths:
  /{user-supplied-webhook-path}:
    post:
      summary: Receives one alert (TraceGuard is the CLIENT).
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [text, alert]
              properties:
                text: { type: string }
                alert:
                  type: object
                  required: [rule, severity, message, pid, comm]
                  properties:
                    rule:      { type: string }
                    severity:  { type: string }
                    message:   { type: string }
                    pid:       { type: integer, format: uint32 }
                    cgroup_id: { type: integer, format: uint64 }
                    container: { type: string }
                    comm:      { type: string }
                    filename:  { type: string }
                    dst:       { type: string }
      responses:
        "2XX": { description: Accepted (any status < 300). }
        "default": { description: ">= 300 logged on stderr, not retried." }
```

## 5. Error handling reference

| Surface | Failure | Behavior |
| --- | --- | --- |
| Startup | bad `-rules` path/YAML | fatal, exit 1 |
| Startup | bad `-log-file` path | fatal, exit 1 |
| Startup | bad `-webhook` URL/scheme | fatal, exit 1 |
| Startup | eBPF load/attach fails (perms, kernel, BTF) | fatal, exit 1 |
| Runtime | ring read error (non-close) | log stderr, sleep 100ms, retry |
| Runtime | decode error | log stderr, skip event |
| Runtime | alert marshal error | log stderr, skip alert |
| Runtime | webhook channel full | drop + log |
| Runtime | webhook POST fails / status ≥300 | log stderr, continue |
| Runtime | container lookup fails | returns `""` or `container:<shortid>`, no error |
</content>
