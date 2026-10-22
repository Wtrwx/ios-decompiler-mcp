from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ValidationError

from ios_decompiler_mcp.core.errors import Code, MCPError
from ios_decompiler_mcp.core.evidence import ErrorDetail, Result, redact
from ios_decompiler_mcp.core.registry import Registry, new_id


@dataclass
class Tool:
    name: str
    description: str
    model: type[BaseModel]
    handler: Callable[[Any], Awaitable[dict[str, Any]]]
    read_only: bool
    timeout: float


class ToolRegistry:
    def __init__(self, registry: Registry, timeout: float):
        self.registry, self.timeout = registry, timeout
        self.tools: dict[str, Tool] = {}

    def add(self, name: str, model: type[BaseModel], handler: Callable[[Any], Awaitable[dict[str, Any]]], description: str, *, read_only: bool = True, timeout: float | None = None) -> None:
        if name in self.tools:
            raise ValueError(f"Duplicate tool: {name}")
        self.tools[name] = Tool(name, description, model, handler, read_only, timeout or self.timeout)

    async def invoke(self, name: str, arguments: dict[str, Any]) -> Result:
        request_id, start = new_id("request"), time.monotonic()
        error: ErrorDetail | None = None
        data: dict[str, Any] | None = None
        self.registry.audit(request_id, name, "started")
        try:
            if name not in self.tools:
                raise MCPError(Code.NOT_FOUND, "Unknown MCP tool")
            tool = self.tools[name]
            request = tool.model.model_validate(arguments)
            data = await asyncio.wait_for(tool.handler(request), tool.timeout)
        except ValidationError as exc:
            error = ErrorDetail(code=Code.INVALID_INPUT, message="Tool input validation failed", details={"errors": [{"location": list(e["loc"]), "message": e["msg"], "type": e["type"]} for e in exc.errors()]})
        except MCPError as exc:
            error = ErrorDetail(code=exc.code, message=exc.message, retryable=exc.retryable, details=redact(exc.details))
        except TimeoutError:
            error = ErrorDetail(code=Code.TIMEOUT, message="Tool execution timed out", retryable=True)
        except asyncio.CancelledError:
            self.registry.audit(request_id, name, "cancelled")
            raise
        except Exception as exc:
            error = ErrorDetail(code=Code.INTERNAL, message="Unexpected adapter failure", details={"reason": type(exc).__name__})
        result = Result(ok=error is None, data=redact(data) if data is not None else None, error=error, request_id=request_id, elapsed_ms=round((time.monotonic() - start) * 1000, 2))
        self.registry.audit(request_id, name, error.code if error else "ok")
        return result
