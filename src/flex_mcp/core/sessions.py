from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from flex_mcp.core.errors import Code, FlexError
from flex_mcp.core.evidence import redact
from flex_mcp.core.registry import Registry


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

    def invalidate(self, reason: str, registry: Registry) -> None:
        self.active = False
        self.reason = reason
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
        raise FlexError(Code.SESSION_INVALID, "Process session is missing or invalidated; attach again", session_id=session_id)
    if session.device_id != device_id:
        raise FlexError(Code.NOT_ALLOWED, "Session belongs to another device")
    return session
