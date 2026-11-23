# Policy Configuration & Preset Guide

## Built-in Presets

| Preset | Mode | Default Action | Primary Use Case |
| :--- | :--- | :--- | :--- |
| `strict_sandbox` | `enforce` | `deny` | Untrusted workloads; strict workspace root, read-only binaries, HTTPS-only, injection blocks output |
| `coding_agent` | `enforce` | `allow` | Day-to-day coding agents; blocks path escapes/SSRF/injection/secrets, allows safe `git`/`pytest`/`rg` |
| `read_only_audit` | `audit` | `allow` | Shadow rollout; logs every violation into the SHA-256 audit DB without blocking tool calls |
| `ctx_pager_hardened` | `enforce` | `deny` | Dedicated allowlist for `ctx-pager` MCP tools; prevents secrets or injected prompts entering memory |

## Dynamic Taint Tracking

When `injection_guard` flags untrusted tool output above `injection.score_threshold`:
1. The engine activates a session taint window for `injection.taint_ttl_calls` subsequent turns.
2. Any call to a tool marked `"taint_sensitive": true` (for example `run_cmd`, `write_file`, `fetch_url`,
   or `ctx_commit`) is blocked immediately with `TAINT_SINK_BLOCKED` while the taint window is active.
3. Read-only inspection tools (for example `read_file`, `list_dir`, `ctx_recall`) remain usable and
   gradually decrement the TTL as safe turns complete.
