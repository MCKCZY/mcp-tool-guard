#!/usr/bin/env python3
"""Install the mcp-tool-guard Agent Skill into Antigravity, Claude Code, Codex, or a custom path."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

_DEFAULT_TARGETS = {
    "antigravity": Path(".agents/skills/mcp-tool-guard"),
    "claude": Path.home() / ".claude" / "skills" / "mcp-tool-guard",
    "codex": Path.home() / ".codex" / "skills" / "mcp-tool-guard",
}


def install_skill(
    *,
    target: str,
    custom_path: str | None = None,
    symlink: bool = False,
    force: bool = False,
) -> Path:
    repo_root = Path(__file__).resolve().parents[1]
    source_dir = repo_root / "skills" / "mcp-tool-guard"
    if not (source_dir / "SKILL.md").is_file():
        raise FileNotFoundError(f"Skill source missing: {source_dir / 'SKILL.md'}")

    if target == "path":
        if not custom_path:
            raise ValueError("--path is required when --target=path")
        dest_dir = Path(custom_path).expanduser().resolve()
    else:
        dest_dir = _DEFAULT_TARGETS[target]
        if not dest_dir.is_absolute():
            dest_dir = (Path.cwd() / dest_dir).resolve()

    if dest_dir.exists() or dest_dir.is_symlink():
        if not force:
            raise FileExistsError(
                f"Destination already exists: {dest_dir}. Re-run with --force to replace."
            )
        if dest_dir.is_symlink() or dest_dir.is_file():
            dest_dir.unlink()
        else:
            shutil.rmtree(dest_dir)

    dest_dir.parent.mkdir(parents=True, exist_ok=True)
    if symlink:
        os.symlink(source_dir, dest_dir)
    else:
        shutil.copytree(source_dir, dest_dir)
        bundled_src = dest_dir / "scripts" / "_lib" / "mcp_tool_guard"
        if not bundled_src.exists():
            shutil.copytree(repo_root / "src" / "mcp_tool_guard", bundled_src)

    shim = dest_dir / "scripts" / "mcp_tool_guard.py"
    if not (dest_dir / "SKILL.md").is_file() or not shim.is_file():
        raise RuntimeError(f"Installation verification failed in {dest_dir}")

    proc = subprocess.run(
        [sys.executable, str(shim), "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"Smoke check failed ({proc.returncode}): {proc.stderr.strip()}")
    return dest_dir


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Install mcp-tool-guard Agent Skill.")
    parser.add_argument(
        "--target",
        required=True,
        choices=["antigravity", "claude", "codex", "path"],
        help="Target skill registry location",
    )
    parser.add_argument("--path", default=None, help="Destination path when --target=path")
    parser.add_argument("--symlink", action="store_true", help="Symlink instead of copying")
    parser.add_argument("--force", action="store_true", help="Replace existing installation")
    args = parser.parse_args(argv)

    dest = install_skill(
        target=args.target,
        custom_path=args.path,
        symlink=args.symlink,
        force=args.force,
    )
    print(f"Installed mcp-tool-guard skill to: {dest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
