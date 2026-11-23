"""Thread-safe, tamper-evident SQLite SHA-256 hash-chained audit logger."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_GENESIS_HASH = "0" * 64


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _compute_hash(
    prev_hash: str,
    direction: str,
    tool_name: str,
    decision: str,
    mode: str,
    args_sha256: str,
    findings_json: str,
    tainted: int,
    created_at: str,
) -> str:
    raw = (
        f"{prev_hash}|{direction}|{tool_name}|{decision}|{mode}|"
        f"{args_sha256}|{findings_json}|{tainted}|{created_at}"
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


class AuditLog:
    """Append-only hash-chained audit log that stores hashes/redacted findings rather than raw secrets."""

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self.db_path = str(db_path)
        self._is_memory = self.db_path == ":memory:"
        if not self._is_memory:
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock, self.conn:
            if not self._is_memory:
                self.conn.execute("PRAGMA journal_mode=WAL;")
            self.conn.execute("PRAGMA synchronous=NORMAL;")
            self.conn.execute("PRAGMA busy_timeout=5000;")
            self.conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE NOT NULL,
                    direction TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    args_sha256 TEXT NOT NULL,
                    findings_json TEXT NOT NULL,
                    tainted INTEGER NOT NULL DEFAULT 0,
                    latency_ms REAL NOT NULL DEFAULT 0.0,
                    prev_hash TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_audit_tool ON audit_events(tool_name);
                CREATE INDEX IF NOT EXISTS idx_audit_decision ON audit_events(decision);
                """
            )

    def close(self) -> None:
        with self._lock:
            self.conn.close()

    @staticmethod
    def hash_payload(payload: Any) -> str:
        canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def record(
        self,
        *,
        direction: str,
        tool_name: str,
        decision: str,
        mode: str,
        payload_for_hash: Any,
        findings: list[dict[str, Any]],
        tainted: bool,
        latency_ms: float,
    ) -> dict[str, Any]:
        args_sha256 = self.hash_payload(payload_for_hash)
        findings_json = json.dumps(findings, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        tainted_int = 1 if tainted else 0
        ts = _utc_now()

        with self._lock, self.conn:
            last_row = self.conn.execute(
                "SELECT seq, content_hash FROM audit_events ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            prev_hash = last_row["content_hash"] if last_row else _GENESIS_HASH
            next_num = (int(last_row["seq"]) + 1) if last_row else 1
            event_id = f"AUD-{next_num:06d}"
            content_hash = _compute_hash(
                prev_hash,
                direction,
                tool_name,
                decision,
                mode,
                args_sha256,
                findings_json,
                tainted_int,
                ts,
            )
            self.conn.execute(
                """
                INSERT INTO audit_events(
                    event_id, direction, tool_name, decision, mode, args_sha256,
                    findings_json, tainted, latency_ms, prev_hash, content_hash, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    direction,
                    tool_name,
                    decision,
                    mode,
                    args_sha256,
                    findings_json,
                    tainted_int,
                    round(float(latency_ms), 3),
                    prev_hash,
                    content_hash,
                    ts,
                ),
            )
        return {
            "event_id": event_id,
            "direction": direction,
            "tool_name": tool_name,
            "decision": decision,
            "content_hash": content_hash,
        }

    def verify_chain(self) -> tuple[bool, list[str]]:
        with self._lock:
            rows = self.conn.execute("SELECT * FROM audit_events ORDER BY seq ASC").fetchall()
        errors: list[str] = []
        expected_prev = _GENESIS_HASH
        for row in rows:
            if row["prev_hash"] != expected_prev:
                errors.append(
                    f"seq={row['seq']} ({row['event_id']}): prev_hash mismatch"
                )
            recomputed = _compute_hash(
                row["prev_hash"],
                row["direction"],
                row["tool_name"],
                row["decision"],
                row["mode"],
                row["args_sha256"],
                row["findings_json"],
                int(row["tainted"]),
                row["created_at"],
            )
            if row["content_hash"] != recomputed:
                errors.append(
                    f"seq={row['seq']} ({row['event_id']}): content_hash tampered"
                )
            expected_prev = row["content_hash"]
        return (len(errors) == 0, errors)

    def recent(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM audit_events ORDER BY seq DESC LIMIT ?", (limit,)
            ).fetchall()
        return [
            {
                "seq": int(r["seq"]),
                "event_id": r["event_id"],
                "direction": r["direction"],
                "tool_name": r["tool_name"],
                "decision": r["decision"],
                "mode": r["mode"],
                "args_sha256": r["args_sha256"],
                "findings": json.loads(r["findings_json"]),
                "tainted": bool(r["tainted"]),
                "latency_ms": float(r["latency_ms"]),
                "prev_hash": r["prev_hash"],
                "content_hash": r["content_hash"],
                "created_at": r["created_at"],
            }
            for r in rows
        ]

    def stats(self) -> dict[str, Any]:
        with self._lock:
            total = self.conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
            by_decision = {
                r["decision"]: r["cnt"]
                for r in self.conn.execute(
                    "SELECT decision, COUNT(*) AS cnt FROM audit_events GROUP BY decision"
                ).fetchall()
            }
            by_direction = {
                r["direction"]: r["cnt"]
                for r in self.conn.execute(
                    "SELECT direction, COUNT(*) AS cnt FROM audit_events GROUP BY direction"
                ).fetchall()
            }
            tainted_events = self.conn.execute(
                "SELECT COUNT(*) FROM audit_events WHERE tainted = 1"
            ).fetchone()[0]
        chain_ok, errors = self.verify_chain()
        return {
            "db_path": self.db_path,
            "total_events": int(total),
            "by_decision": by_decision,
            "by_direction": by_direction,
            "tainted_events": int(tainted_events),
            "chain_ok": chain_ok,
            "chain_errors": errors,
        }

    def export_jsonl(self, output_path: str | Path) -> int:
        with self._lock:
            rows = self.conn.execute("SELECT * FROM audit_events ORDER BY seq ASC").fetchall()
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(
                    json.dumps(
                        {
                            "seq": int(r["seq"]),
                            "event_id": r["event_id"],
                            "direction": r["direction"],
                            "tool_name": r["tool_name"],
                            "decision": r["decision"],
                            "mode": r["mode"],
                            "args_sha256": r["args_sha256"],
                            "findings": json.loads(r["findings_json"]),
                            "tainted": bool(r["tainted"]),
                            "latency_ms": float(r["latency_ms"]),
                            "prev_hash": r["prev_hash"],
                            "content_hash": r["content_hash"],
                            "created_at": r["created_at"],
                        },
                        ensure_ascii=False,
                    )
                    + "\n"
                )
        return len(rows)
