from __future__ import annotations

import fcntl
import json
import os
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any, BinaryIO

from ios_decompiler_mcp.core.errors import Code, MCPError
from ios_decompiler_mcp.core.evidence import redact


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


class Registry:
    """Durable metadata only. Live pointers/SSH/Frida handles never survive a host restart."""

    def __init__(self, directory: Path):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = directory / "state.sqlite3"
        self.server_lock: BinaryIO | None = None
        self.db = sqlite3.connect(self.path, timeout=10)
        os.chmod(self.path, 0o600)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS records (
                id TEXT PRIMARY KEY, kind TEXT NOT NULL, status TEXT NOT NULL,
                data TEXT NOT NULL, updated REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS approvals (
                id TEXT PRIMARY KEY, action TEXT NOT NULL, scope TEXT NOT NULL,
                status TEXT NOT NULL, expires REAL NOT NULL, created REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT, timestamp REAL NOT NULL,
                request_id TEXT NOT NULL, tool TEXT NOT NULL, status TEXT NOT NULL, data TEXT NOT NULL
            );
        """)
        self.db.commit()

    def acquire_server_lock(self) -> None:
        lock = self.path.with_name("server.lock").open("a+b")
        os.fchmod(lock.fileno(), 0o600)
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            lock.close()
            raise MCPError(Code.UNAVAILABLE, "Another iOS Decompiler MCP server owns this state directory; use one server per state directory") from exc
        self.server_lock = lock

    def invalidate_live_sessions(self) -> None:
        self.db.execute("UPDATE records SET status='invalidated' WHERE kind IN ('device_session','process_session','ida_session','job') AND status IN ('active','running','pending')")
        self.db.commit()

        # A host crash cannot prove what dpkg did. Preserve enough state for a
        # fresh, explicitly approved recovery instead of issuing blind mutations.
        for kind, phases in (("deployment", {"staging", "installing"}), ("workflow", {"inspecting", "building", "verifying"})):
            for record in self.list(kind):
                if record.get("phase") in phases:
                    record["interrupted_phase"] = record["phase"]
                    record["phase"] = "interrupted"
                    self.save(record["id"], kind, record, "interrupted")

    def save(self, record_id: str, kind: str, data: dict[str, Any], status: str = "active") -> None:
        self.db.execute("INSERT OR REPLACE INTO records VALUES (?,?,?,?,?)", (record_id, kind, status, json.dumps(data), time.time()))
        self.db.commit()

    def get(self, record_id: str, kind: str | None = None) -> dict[str, Any]:
        row = self.db.execute("SELECT kind,status,data FROM records WHERE id=?", (record_id,)).fetchone()
        if row is None or (kind is not None and row[0] != kind):
            raise MCPError(Code.NOT_FOUND, "Unknown record", record_id=record_id)
        return {**json.loads(row[2]), "id": record_id, "kind": row[0], "status": row[1]}

    def list(self, kind: str) -> list[dict[str, Any]]:
        rows = self.db.execute("SELECT id FROM records WHERE kind=? ORDER BY updated DESC LIMIT 1000", (kind,)).fetchall()
        return [self.get(row[0]) for row in rows]

    def audit(self, request_id: str, tool: str, status: str, data: dict[str, Any] | None = None) -> None:
        self.db.execute("INSERT INTO audit(timestamp,request_id,tool,status,data) VALUES (?,?,?,?,?)", (time.time(), request_id, tool, status, json.dumps(redact(data or {}))))
        self.db.commit()

    def close(self) -> None:
        self.db.close()
        if self.server_lock:
            self.server_lock.close()
            self.server_lock = None
