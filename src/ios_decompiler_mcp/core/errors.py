from __future__ import annotations

from enum import StrEnum
from typing import Any


class Code(StrEnum):
    INVALID_INPUT = "INVALID_INPUT"
    NOT_ALLOWED = "NOT_ALLOWED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    APPROVAL_INVALID = "APPROVAL_INVALID"
    NOT_FOUND = "NOT_FOUND"
    UNAVAILABLE = "UNAVAILABLE"
    SSH_ERROR = "SSH_ERROR"
    FRIDA_ERROR = "FRIDA_ERROR"
    SESSION_INVALID = "SESSION_INVALID"
    TIMEOUT = "TIMEOUT"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
    BUILD_FAILED = "BUILD_FAILED"
    DEPLOY_FAILED = "DEPLOY_FAILED"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"
    IDA_ERROR = "IDA_ERROR"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    INTERNAL = "INTERNAL"


class MCPError(Exception):
    def __init__(self, code: Code, message: str, *, retryable: bool = False, **details: Any):
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable
        self.details = details
