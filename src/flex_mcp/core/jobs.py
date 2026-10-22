from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

from flex_mcp.core.errors import Code, FlexError
from flex_mcp.core.registry import Registry, new_id


class Jobs:
    def __init__(self, registry: Registry, limit: int):
        self.registry, self.limit = registry, limit
        self.tasks: dict[str, asyncio.Task[None]] = {}

    def start(self, operation: str, work: Callable[[], Awaitable[dict[str, Any]]]) -> dict[str, Any]:
        if sum(not task.done() for task in self.tasks.values()) >= self.limit:
            raise FlexError(Code.LIMIT_EXCEEDED, "Too many active jobs")
        job_id = new_id("job")
        self.registry.save(job_id, "job", {"operation": operation}, "running")

        async def run() -> None:
            try:
                result = await work()
                self.registry.save(job_id, "job", {"operation": operation, "result": result}, "completed")
            except asyncio.CancelledError:
                self.registry.save(job_id, "job", {"operation": operation}, "cancelled")
                raise
            except FlexError as exc:
                self.registry.save(job_id, "job", {"operation": operation, "error": {"code": exc.code, "message": exc.message, "details": exc.details}}, "failed")
            except Exception:
                self.registry.save(job_id, "job", {"operation": operation, "error": {"code": Code.INTERNAL, "message": "Unexpected job failure; see operator diagnostics"}}, "failed")

        self.tasks[job_id] = asyncio.create_task(run())
        self.tasks[job_id].add_done_callback(lambda _: self.tasks.pop(job_id, None))
        return {"job_id": job_id, "status": "running"}

    async def cancel(self, job_id: str) -> dict[str, Any]:
        task = self.tasks.get(job_id)
        if task and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        return self.registry.get(job_id, "job")

    async def close(self) -> None:
        tasks = list(self.tasks.values())
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
