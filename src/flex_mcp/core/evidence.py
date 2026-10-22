from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

_SECRET = re.compile(r"password|passwd|secret|authorization|cookie|credential|access.?token|private.?key", re.I)
_BEARER = re.compile(r"(?i)\b(Bearer\s+)[A-Za-z0-9._~+/=-]+")
_ASSIGNMENT = re.compile(r"(?i)\b(password|passwd|secret|access_token|authorization|cookie)\s*[:=]\s*[^\s,;]+")
_PEM = re.compile(r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", re.S)


def redact(value: Any, *, depth: int = 0) -> Any:
    if depth > 20:
        return "[TRUNCATED]"
    if isinstance(value, dict):
        return {str(k): "[REDACTED]" if _SECRET.search(str(k)) else redact(v, depth=depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(x, depth=depth + 1) for x in value[:10000]]
    if isinstance(value, str):
        return _ASSIGNMENT.sub(r"\1=[REDACTED]", _BEARER.sub(r"\1[REDACTED]", _PEM.sub("[REDACTED]", value)))[:262144]
    return value


class Evidence(BaseModel):
    kind: str
    source: str
    observed: bool = True
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    data: dict[str, Any] = Field(default_factory=dict)


class ErrorDetail(BaseModel):
    code: str
    message: str
    retryable: bool = False
    details: dict[str, Any] = Field(default_factory=dict)


class Result(BaseModel):
    ok: bool
    data: dict[str, Any] | None = None
    error: ErrorDetail | None = None
    request_id: str
    elapsed_ms: float
