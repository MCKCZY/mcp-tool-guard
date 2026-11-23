"""Command injection, shell metacharacter, wrapper bypass, and GTFOBins flag guard."""

from __future__ import annotations

import shlex
from pathlib import Path

from mcp_tool_guard.guards import GuardFinding
from mcp_tool_guard.policy import CommandPolicy

_SHELL_WRAPPERS = frozenset(
    {
        "sh",
        "bash",
        "zsh",
        "dash",
        "ksh",
        "fish",
        "ash",
        "csh",
        "tcsh",
        "cmd",
        "cmd.exe",
        "powershell",
        "pwsh",
        "eval",
        "exec",
        "sudo",
        "doas",
        "su",
    }
)

_TRANSPARENT_WRAPPERS = frozenset(
    {"env", "nohup", "timeout", "nice", "stdbuf", "ionice", "time", "command", "xargs"}
)

_PYTHON_BINS = frozenset({"python", "python3", "python2"})
_SCRIPT_EVAL_BINS = frozenset({"node", "nodejs", "deno", "bun", "perl", "ruby", "php", "lua"})
_EXFIL_DOWNLOAD_BINS = frozenset({"curl", "wget"})


def _scan_shell_metachars(cmd: str) -> str | None:
    """Detect unquoted shell operators and command substitutions (even inside double quotes)."""
    in_single = False
    in_double = False
    escaped = False
    n = len(cmd)

    for i, ch in enumerate(cmd):
        if ch in ("\n", "\r"):
            return "newline"
        if escaped:
            escaped = False
            continue
        if ch == "\\" and not in_single:
            escaped = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            continue

        # POSIX shells still expand `$(...)` and backticks inside double quotes.
        if not in_single:
            if ch == "`":
                return "backtick"
            if ch == "$" and i + 1 < n and cmd[i + 1] in ("(", "{"):
                return f"${cmd[i + 1]}"

        if not in_single and not in_double:
            if ch in (";", "|", "&", ">", "<", "(", ")"):
                return ch
    return None


def _unwrap_tokens(tokens: list[str], allowed_bins: set[str]) -> tuple[list[str], str | None]:
    """Skip transparent wrappers like `env` or `timeout` to inspect the underlying binary."""
    idx = 0
    while idx < len(tokens):
        base = Path(tokens[idx]).name
        if base in _SHELL_WRAPPERS and base not in allowed_bins:
            return tokens[idx:], base
        if base not in _TRANSPARENT_WRAPPERS:
            return tokens[idx:], None

        # Advance past wrapper name and its flags/env assignments.
        idx += 1
        if base == "timeout" and idx < len(tokens):
            while idx < len(tokens) and tokens[idx].startswith("-"):
                idx += 1
            if idx < len(tokens) and (tokens[idx][0].isdigit()):
                idx += 1
            continue
        while idx < len(tokens):
            tok = tokens[idx]
            if tok == "--":
                idx += 1
                break
            if tok.startswith("-") or (base == "env" and "=" in tok and not tok.startswith("/")):
                idx += 1
                continue
            break
    return [], None


def _check_dangerous_flags(base_bin: str, args: list[str]) -> list[GuardFinding]:
    findings: list[GuardFinding] = []
    joined = " ".join(args)

    if base_bin in _PYTHON_BINS:
        for i, arg in enumerate(args):
            if arg == "-c" or (arg.startswith("-") and not arg.startswith("--") and "c" in arg[1:]):
                findings.append(
                    GuardFinding(
                        guard="command_guard",
                        code="DANGEROUS_INLINE_CODE",
                        severity="critical",
                        message=f"Inline Python execution flag '{arg}' is blocked",
                    )
                )
                break
            if arg == "-m" and i + 1 < len(args) and args[i + 1] in (
                "http.server",
                "SimpleHTTPServer",
                "smtpd",
                "pip",
            ):
                findings.append(
                    GuardFinding(
                        guard="command_guard",
                        code="DANGEROUS_PYTHON_MODULE",
                        severity="high",
                        message=f"Blocked risky Python module invocation '-m {args[i + 1]}'",
                    )
                )
                break

    elif base_bin in _SCRIPT_EVAL_BINS:
        for arg in args:
            if arg in ("-e", "--eval", "-p", "--print", "-r", "-E"):
                findings.append(
                    GuardFinding(
                        guard="command_guard",
                        code="DANGEROUS_INLINE_CODE",
                        severity="critical",
                        message=f"Inline code evaluation flag '{arg}' blocked for {base_bin}",
                    )
                )
                break

    elif base_bin == "find":
        bad_find = {"-exec", "-execdir", "-ok", "-okdir", "-delete", "-fls", "-fprint"}
        hit = next((a for a in args if a in bad_find), None)
        if hit:
            findings.append(
                GuardFinding(
                    guard="command_guard",
                    code="DANGEROUS_FIND_FLAG",
                    severity="critical",
                    message=f"Blocked find execution/deletion flag '{hit}'",
                )
            )

    elif base_bin == "tar":
        for arg in args:
            if any(
                arg == flag or arg.startswith(f"{flag}=")
                for flag in ("--checkpoint-action", "--to-command", "--use-compress-program", "-I")
            ):
                findings.append(
                    GuardFinding(
                        guard="command_guard",
                        code="DANGEROUS_TAR_FLAG",
                        severity="critical",
                        message=f"Blocked tar command-execution flag '{arg}'",
                    )
                )
                break

    elif base_bin == "git":
        for i, arg in enumerate(args):
            if arg in ("--upload-pack", "--receive-pack", "--exec") or arg.startswith(
                ("--upload-pack=", "--receive-pack=", "--exec=")
            ):
                findings.append(
                    GuardFinding(
                        guard="command_guard",
                        code="DANGEROUS_GIT_FLAG",
                        severity="critical",
                        message=f"Blocked git external-command flag '{arg}'",
                    )
                )
                break
            if arg == "-c" and i + 1 < len(args):
                cfg = args[i + 1].lower()
                if any(
                    cfg.startswith(p)
                    for p in ("core.sshcommand=", "core.fsmonitor=", "alias.", "credential.helper=", "diff.external=")
                ):
                    findings.append(
                        GuardFinding(
                            guard="command_guard",
                            code="DANGEROUS_GIT_CONFIG",
                            severity="critical",
                            message=f"Blocked git config execution override '{args[i + 1]}'",
                        )
                    )
                    break

    elif base_bin in _EXFIL_DOWNLOAD_BINS:
        exfil_flags = {
            "-d",
            "--data",
            "--data-raw",
            "--data-binary",
            "--data-urlencode",
            "-F",
            "--form",
            "-T",
            "--upload-file",
            "--post-file",
            "--post-data",
            "-K",
            "--config",
        }
        for arg in args:
            if arg in exfil_flags or any(arg.startswith(f"{f}=") for f in exfil_flags):
                findings.append(
                    GuardFinding(
                        guard="command_guard",
                        code="EXFIL_UPLOAD_FLAG",
                        severity="high",
                        message=f"Blocked data upload/exfiltration flag '{arg}' for {base_bin}",
                    )
                )
                break

    elif base_bin in ("awk", "gawk", "mawk", "nawk"):
        if "system(" in joined or "getline" in joined:
            findings.append(
                GuardFinding(
                    guard="command_guard",
                    code="DANGEROUS_AWK_EXPR",
                    severity="critical",
                    message="Blocked awk shell execution expression",
                )
            )

    elif base_bin == "chmod":
        if any(a in ("+s", "u+s", "g+s", "777", "4755", "2755") for a in args):
            findings.append(
                GuardFinding(
                    guard="command_guard",
                    code="DANGEROUS_CHMOD_MODE",
                    severity="high",
                    message="Blocked unsafe setuid or world-writable chmod mode",
                )
            )

    return findings


def check_command(command: object, policy: CommandPolicy) -> list[GuardFinding]:
    """Inspect a command string or argv list against metacharacter, wrapper, binary, and flag policies."""
    if isinstance(command, list):
        if not command or not all(isinstance(x, str) and x for x in command):
            return [
                GuardFinding(
                    guard="command_guard",
                    code="INVALID_COMMAND",
                    severity="high",
                    message="Command argv list must contain non-empty strings",
                )
            ]
        tokens = list(command)
        raw_str = " ".join(tokens)
    elif isinstance(command, str):
        raw_str = command.strip()
        if not raw_str:
            return [
                GuardFinding(
                    guard="command_guard",
                    code="EMPTY_COMMAND",
                    severity="high",
                    message="Command must be non-empty",
                )
            ]
        if "\x00" in raw_str:
            return [
                GuardFinding(
                    guard="command_guard",
                    code="COMMAND_NULL_BYTE",
                    severity="critical",
                    message="Command contains null byte",
                )
            ]
        if len(raw_str) > policy.max_command_length:
            return [
                GuardFinding(
                    guard="command_guard",
                    code="COMMAND_TOO_LONG",
                    severity="medium",
                    message=f"Command length exceeds {policy.max_command_length}",
                )
            ]
        if policy.forbid_shell_metachars:
            meta = _scan_shell_metachars(raw_str)
            if meta is not None:
                return [
                    GuardFinding(
                        guard="command_guard",
                        code="SHELL_METACHAR_BLOCKED",
                        severity="critical",
                        message=f"Blocked shell chaining/substitution operator '{meta}'",
                        detail={"operator": meta},
                    )
                ]
        try:
            tokens = shlex.split(raw_str, posix=True)
        except ValueError as exc:
            return [
                GuardFinding(
                    guard="command_guard",
                    code="COMMAND_PARSE_ERROR",
                    severity="high",
                    message=f"Malformed command quoting: {exc}",
                )
            ]
    else:
        return [
            GuardFinding(
                guard="command_guard",
                code="INVALID_COMMAND_TYPE",
                severity="high",
                message="Command must be a string or argv list",
            )
        ]

    if not tokens:
        return [
            GuardFinding(
                guard="command_guard",
                code="EMPTY_COMMAND",
                severity="high",
                message="Parsed command contains no executable token",
            )
        ]

    allowed_set = {Path(b).name for b in policy.allowed_binaries}
    denied_set = {Path(b).name for b in policy.denied_binaries}

    unwrapped, disallowed_wrapper = _unwrap_tokens(tokens, allowed_set)
    if disallowed_wrapper is not None:
        return [
            GuardFinding(
                guard="command_guard",
                code="DISALLOWED_SHELL_WRAPPER",
                severity="critical",
                message=f"Blocked shell or privilege wrapper '{disallowed_wrapper}'",
                detail={"wrapper": disallowed_wrapper},
            )
        ]

    if not unwrapped:
        return [
            GuardFinding(
                guard="command_guard",
                code="MISSING_TARGET_BINARY",
                severity="high",
                message="Wrapper invocation has no target binary",
            )
        ]

    base_bin = Path(unwrapped[0]).name
    findings: list[GuardFinding] = []

    if base_bin in denied_set:
        findings.append(
            GuardFinding(
                guard="command_guard",
                code="DENIED_BINARY",
                severity="critical",
                message=f"Executable '{base_bin}' is explicitly denied",
                detail={"binary": base_bin},
            )
        )
    elif allowed_set and base_bin not in allowed_set:
        findings.append(
            GuardFinding(
                guard="command_guard",
                code="BINARY_NOT_ALLOWLISTED",
                severity="high",
                message=f"Executable '{base_bin}' is not in allowed_binaries",
                detail={"binary": base_bin},
            )
        )

    if policy.forbid_dangerous_flags:
        findings.extend(_check_dangerous_flags(base_bin, unwrapped[1:]))

    return findings
