from __future__ import annotations

import asyncio
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from vesper.core.errors import Code, MCPError
from vesper.core.evidence import redact
from vesper.core.registry import Registry


@dataclass
class ProcessSession:
    id: str
    device_id: str
    bundle_id: str
    pid: int
    handle: Any
    script: Any = None
    active: bool = True
    reason: str | None = None
    sequence: int = 0
    dropped: int = 0
    events: deque[dict[str, Any]] = field(default_factory=deque)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    last_used: float = field(default_factory=time.monotonic)
    in_flight: int = 0
    hooks: set[str] = field(default_factory=set)
    on_invalidate: Callable[[ProcessSession], None] | None = None

    def invalidate(self, reason: str, registry: Registry) -> None:
        if not self.active:
            return
        self.active = False
        self.reason = reason
        if self.on_invalidate:
            self.on_invalidate(self)
        registry.save(self.id, "process_session", self.metadata(), "invalidated")

    def metadata(self) -> dict[str, Any]:
        return {"session_id": self.id, "device_id": self.device_id, "bundle_id": self.bundle_id, "pid": self.pid, "reason": self.reason}

    def event(self, payload: dict[str, Any], capacity: int) -> None:
        self.sequence += 1
        if len(self.events) >= capacity:
            self.events.popleft()
            self.dropped += 1
        self.events.append({**redact(payload), "sequence": self.sequence})


def require_session(sessions: dict[str, ProcessSession], device_id: str, session_id: str) -> ProcessSession:
    session = sessions.get(session_id)
    if session is None or not session.active:
        raise MCPError(Code.SESSION_INVALID, "Process session is missing or invalidated; attach again", session_id=session_id)
    if session.device_id != device_id:
        raise MCPError(Code.NOT_ALLOWED, "Session belongs to another device")
    return session
