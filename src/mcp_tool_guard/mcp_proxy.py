"""Transparent bidirectional stdio JSON-RPC 2.0 MCP security proxy."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from typing import Any, Sequence, TextIO

from mcp_tool_guard.engine import ToolGuardEngine
from mcp_tool_guard.policy import DecisionAction


class McpSecurityProxy:
    """Intercepts client<->upstream MCP JSON-RPC traffic to enforce ingress and egress policies."""

    def __init__(self, engine: ToolGuardEngine) -> None:
        self.engine = engine
        self._state_lock = threading.Lock()
        self._call_cond = threading.Condition(self._state_lock)
        self._pending_calls: dict[str, str] = {}
        self._pending_lists: set[str] = set()
        self._upstream_closed: bool = False

    def wait_for_inflight_calls(self, timeout: float = 10.0) -> None:
        """Serialize pipelined `tools/call` requests so egress taint from call N protects call N+1."""
        with self._call_cond:
            self._call_cond.wait_for(
                lambda: not self._pending_calls or self._upstream_closed,
                timeout=timeout,
            )

    def mark_upstream_closed(self) -> None:
        with self._call_cond:
            self._upstream_closed = True
            self._pending_calls.clear()
            self._call_cond.notify_all()

    @staticmethod
    def _id_key(req_id: Any) -> str:
        return json.dumps(req_id, sort_keys=True, separators=(",", ":"))

    def process_client_message(self, msg: Any) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        """Inspect a client->upstream JSON-RPC message.

        Returns `(forward_to_upstream, immediate_reply_to_client)`.
        """
        if not isinstance(msg, dict):
            return None, {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32600, "message": "Invalid Request"},
            }

        method = msg.get("method")
        req_id = msg.get("id")
        params = msg.get("params")

        if method == "tools/list" and req_id is not None:
            with self._state_lock:
                self._pending_lists.add(self._id_key(req_id))
            return msg, None

        if method == "tools/call":
            if not isinstance(params, dict) or not isinstance(params.get("name"), str):
                return None, {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32602, "message": "Invalid tools/call params"},
                }
            tool_name = params["name"]
            raw_args = params.get("arguments")
            if raw_args is None:
                args: dict[str, Any] = {}
            elif isinstance(raw_args, dict):
                args = raw_args
            else:
                return None, {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32602, "message": "Tool arguments must be an object"},
                }

            decision = self.engine.check_call(tool_name, args)
            if not decision.allowed:
                reasons = "; ".join(f"[{f.code}] {f.message}" for f in decision.findings)
                reply: dict[str, Any] | None = None
                if req_id is not None:
                    reply = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [
                                {
                                    "type": "text",
                                    "text": f"Blocked by mcp-tool-guard: {reasons}",
                                }
                            ],
                            "isError": True,
                            "_guard": decision.to_dict(),
                        },
                    }
                return None, reply

            if req_id is not None:
                with self._state_lock:
                    self._pending_calls[self._id_key(req_id)] = tool_name
            return msg, None

        return msg, None

    def process_upstream_message(self, msg: Any) -> dict[str, Any]:
        """Inspect and sanitize an upstream->client JSON-RPC response."""
        if not isinstance(msg, dict):
            return msg

        req_id = msg.get("id")
        if req_id is None:
            return msg

        key = self._id_key(req_id)
        is_list = False
        tool_name: str | None = None
        with self._state_lock:
            if key in self._pending_lists:
                self._pending_lists.remove(key)
                is_list = True
            elif key in self._pending_calls:
                tool_name = self._pending_calls[key]

        result = msg.get("result")
        if not isinstance(result, dict):
            if tool_name is not None:
                with self._call_cond:
                    self._pending_calls.pop(key, None)
                    self._call_cond.notify_all()
            return msg

        if is_list and isinstance(result.get("tools"), list):
            filtered_tools = [
                t
                for t in result["tools"]
                if isinstance(t, dict) and self.engine.is_tool_visible(str(t.get("name", "")))
            ]
            updated_msg = dict(msg)
            updated_result = dict(result)
            updated_result["tools"] = filtered_tools
            updated_msg["result"] = updated_result
            return updated_msg

        if tool_name is not None:
            try:
                if isinstance(result.get("content"), list):
                    new_content: list[Any] = []
                    any_denied = bool(result.get("isError", False))
                    for block in result["content"]:
                        if (
                            isinstance(block, dict)
                            and block.get("type") == "text"
                            and isinstance(block.get("text"), str)
                        ):
                            egress = self.engine.filter_result(tool_name, block["text"])
                            new_block = dict(block)
                            new_block["text"] = egress.text
                            new_content.append(new_block)
                            if egress.action == DecisionAction.DENY:
                                any_denied = True
                        else:
                            new_content.append(block)
                    updated_msg = dict(msg)
                    updated_result = dict(result)
                    updated_result["content"] = new_content
                    updated_result["isError"] = any_denied
                    updated_msg["result"] = updated_result
                    return updated_msg
            finally:
                with self._call_cond:
                    self._pending_calls.pop(key, None)
                    self._call_cond.notify_all()

        return msg

    def run_stdio_bridge(
        self,
        upstream_cmd: Sequence[str],
        *,
        client_in: TextIO | None = None,
        client_out: TextIO | None = None,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
    ) -> int:
        """Spawn an upstream stdio MCP process and transparently guard all JSON-RPC traffic."""
        cin = client_in or sys.stdin
        cout = client_out or sys.stdout
        out_lock = threading.Lock()
        up_in_lock = threading.Lock()

        merged_env = os.environ.copy()
        if env:
            merged_env.update(env)

        proc = subprocess.Popen(
            list(upstream_cmd),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            text=True,
            encoding="utf-8",
            bufsize=1,
            env=merged_env,
            cwd=cwd,
        )
        assert proc.stdin is not None
        assert proc.stdout is not None

        def _write_client(obj: dict[str, Any]) -> None:
            line = json.dumps(obj, ensure_ascii=False) + "\n"
            with out_lock:
                cout.write(line)
                cout.flush()

        def _pump_client_to_upstream() -> None:
            try:
                for line in cin:
                    stripped = line.strip()
                    if not stripped:
                        continue
                    try:
                        msg = json.loads(stripped)
                    except json.JSONDecodeError as exc:
                        _write_client(
                            {
                                "jsonrpc": "2.0",
                                "id": None,
                                "error": {"code": -32700, "message": f"Parse error: {exc}"},
                            }
                        )
                        continue
                    if isinstance(msg, dict) and msg.get("method") == "tools/call":
                        self.wait_for_inflight_calls()
                    forward, immediate = self.process_client_message(msg)
                    if immediate is not None:
                        _write_client(immediate)
                    if forward is not None:
                        with up_in_lock:
                            if proc.stdin and not proc.stdin.closed:
                                proc.stdin.write(json.dumps(forward, ensure_ascii=False) + "\n")
                                proc.stdin.flush()
            except BrokenPipeError:
                pass
            finally:
                with up_in_lock:
                    if proc.stdin and not proc.stdin.closed:
                        try:
                            proc.stdin.close()
                        except OSError:
                            pass

        def _pump_upstream_to_client() -> None:
            try:
                for line in proc.stdout:  # type: ignore[union-attr]
                    stripped = line.strip()
                    if not stripped:
                        continue
                    try:
                        msg = json.loads(stripped)
                    except json.JSONDecodeError:
                        with out_lock:
                            cout.write(line if line.endswith("\n") else line + "\n")
                            cout.flush()
                        continue
                    sanitized = self.process_upstream_message(msg)
                    _write_client(sanitized)
            except BrokenPipeError:
                pass
            finally:
                self.mark_upstream_closed()

        t_up = threading.Thread(target=_pump_client_to_upstream, daemon=True)
        t_down = threading.Thread(target=_pump_upstream_to_client, daemon=True)
        t_up.start()
        t_down.start()

        try:
            t_up.join()
            try:
                proc.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                proc.terminate()
                try:
                    proc.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            t_down.join(timeout=2.0)
        finally:
            for stream in (proc.stdin, proc.stdout):
                if stream is not None and not stream.closed:
                    try:
                        stream.close()
                    except OSError:
                        pass
        return int(proc.returncode or 0)
