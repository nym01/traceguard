# TraceGuard — Handoff Documentation Index

Complete project handoff package. Start with **PROJECT_OVERVIEW** for humans, or
**LLM_CONTEXT** to make an LLM productive from a single file.

| Doc | Covers |
| --- | --- |
| [PROJECT_OVERVIEW](./PROJECT_OVERVIEW.md) | Executive summary, purpose, users, features, status, stack |
| [ARCHITECTURE](./ARCHITECTURE.md) | System overview, components, concurrency, eBPF/CO-RE, auth |
| [DOMAIN_MODEL](./DOMAIN_MODEL.md) | Core concepts, the 4 detection rules, assumptions, edge cases |
| [DATA_MODELS](./DATA_MODELS.md) | Kernel structs, unified Event, RuleConfig, Alert, ER diagram |
| [API_REFERENCE](./API_REFERENCE.md) | CLI flags, JSON output contract, webhook POST, OpenAPI sketch |
| [WORKFLOWS](./WORKFLOWS.md) | Sequence diagrams: event lifecycle, startup, shutdown, validation |
| [DEVELOPMENT_GUIDE](./DEVELOPMENT_GUIDE.md) | Setup, build, run, test, debug, common tasks, release |
| [OPERATIONS_GUIDE](./OPERATIONS_GUIDE.md) | Config/env, deployment, monitoring, logging, rollback |
| [CODE_QUALITY_REVIEW](./CODE_QUALITY_REVIEW.md) | Strengths, weaknesses, risks, security, testing analysis |
| [FEATURE_INVENTORY](./FEATURE_INVENTORY.md) | Every feature with files, deps, behavior, implementation |
| [CHANGE_IMPACT_MAP](./CHANGE_IMPACT_MAP.md) | "If you change X…" blast-radius map |
| [LLM_CONTEXT](./LLM_CONTEXT.md) | Single-file productivity package for an LLM |
| [KNOWLEDGE_GRAPH](./KNOWLEDGE_GRAPH.md) | Components, relationships, dependencies as graphs/tables |

**Primary sources in repo:** `README.md` (what/how), `DESIGN.md` (why),
`main.go`, `rules.go`, `cgroup.go`, `webhook.go`, `bpf/*.bpf.c`, `validate/`.

> All conclusions are drawn from the code as of this writing; assumptions are
> labeled inline (e.g. cgroup-v2/Docker dependence, x86_64 build flags). Where
> something can't be determined from the repo (e.g. semantic-version release
> policy), the docs say so.
