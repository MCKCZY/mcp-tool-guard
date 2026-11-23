# Threat Mapping & Guard Coverage

| Threat Category | Attack Vectors Covered | Guard Module | Residual Boundary |
| :--- | :--- | :--- | :--- |
| Path Traversal & Symlink Escape | `../`, prefix collision (`/ws_evil`), `os.path.realpath` symlink escape on non-existent leaves, `.env`/`.ssh`/`*.pem` | `path_guard` | Kernel MAC / mount namespaces still needed for native binary syscalls |
| Command & GTFOBins Injection | `;`, `\|`, `$(...)` inside double quotes, backticks, `sudo`/`env`/`bash -c`, `python3 -c`, `find -exec`, `tar --to-command`, `git -c core.sshCommand` | `command_guard` | Custom compiled project binaries outside known GTFOBins |
| SSRF & IP Obfuscation | `169.254.169.254`, decimal/hex/octal/shorthand IPv4, `[::ffff:127.0.0.1]`, NAT64 `64:ff9b::`, `file://`, `gopher://`, userinfo `@`, DNS rebinding | `ssrf_guard` | TOCTOU DNS rebinding between proxy check and upstream connect without socket-level pinning |
| Credential Leakage (DLP) | OpenAI/Anthropic/GitHub/AWS/Google/Slack/JWT/PEM/DB URLs + contextual Shannon entropy >= 4.3 (`[REDACTED:KIND:hash6]`) | `dlp_guard` | Novel custom secret formats lacking prefix and key assignment context |
| Indirect Prompt Injection | EN/ZH overrides, role delimiters, Unicode Tag `U+E0000` smuggling, NFKC folding, Base64 payloads + dynamic taint sinks | `injection_guard` | Non-pattern-based subtle semantic persuasion without override/exfil/obfuscation signals |
| Runaway Loops & Tampering | Sliding-window RPM burst, repeated identical tool-call signature, SHA-256 forward hash-chained SQLite `audit_events` | `rate_guard` / `audit` | Does not inspect kernel process memory outside the Python/MCP process |
