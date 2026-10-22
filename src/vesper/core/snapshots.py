"""Bounded immutable UI captures. Reading a page never calls the device."""
from __future__ import annotations

import json
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from vesper.config import Settings
from vesper.core.errors import Code, MCPError


@dataclass(frozen=True)
class SnapshotEntry:
    device_id: str
    session_id: str
    captured_at: str
    expires: float
    payload: bytes


class SnapshotCache:
    def __init__(self, settings: Settings, release: Callable[[str, str], None]):
        self.settings, self.release = settings, release
        self.entries: OrderedDict[str, SnapshotEntry] = OrderedDict()
        self.bytes = 0

    def discard(self, snapshot_id: str) -> None:
        entry = self.entries.pop(snapshot_id, None)
        if entry:
            self.bytes -= len(entry.payload)
            self.release(entry.session_id, snapshot_id)

    def expire(self) -> None:
        now = time.monotonic()
        for key, entry in list(self.entries.items()):
            if entry.expires <= now:
                self.discard(key)

    def invalidate(self, session_id: str) -> None:
        for key, entry in list(self.entries.items()):
            if entry.session_id == session_id:
                self.discard(key)

    def store(self, snapshot_id: str, device_id: str, session_id: str, data: dict[str, Any], started: float) -> None:
        self.expire()
        payload = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode()
        if len(payload) > self.settings.snapshot_max_bytes:
            self.release(session_id, snapshot_id)
            raise MCPError(Code.LIMIT_EXCEEDED, "Snapshot exceeds the configured cache byte limit; reduce max_nodes or fields")
        while self.entries and (len(self.entries) >= self.settings.snapshot_max_count or self.bytes + len(payload) > self.settings.snapshot_max_bytes):
            self.discard(next(iter(self.entries)))
        self.entries[snapshot_id] = SnapshotEntry(device_id, session_id, data.get("captured_at") or datetime.now(UTC).isoformat(), started + self.settings.snapshot_ttl, payload)
        self.bytes += len(payload)

    def page(self, snapshot_id: str, device_id: str, session_id: str, offset: int, limit: int) -> dict[str, Any]:
        self.expire()
        entry = self.entries.get(snapshot_id)
        if entry is None:
            raise MCPError(Code.NOT_FOUND, "Snapshot expired or was evicted; request a new live capture", snapshot_id=snapshot_id)
        if (entry.device_id, entry.session_id) != (device_id, session_id):
            raise MCPError(Code.NOT_ALLOWED, "Snapshot belongs to another device or process session")
        self.entries.move_to_end(snapshot_id)
        data = json.loads(entry.payload)
        nodes = data.pop("views", [])
        next_offset = offset + limit if offset + limit < len(nodes) else None
        return {**data, "views": nodes[offset:offset + limit], "snapshot_id": snapshot_id,
                "captured_at": entry.captured_at, "expires_in_seconds": max(0, round(entry.expires - time.monotonic(), 3)),
                "total": len(nodes), "next_offset": next_offset,
                "next_cursor": {"snapshot_id": snapshot_id, "offset": next_offset} if next_offset is not None else None}
