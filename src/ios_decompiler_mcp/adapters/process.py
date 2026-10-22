from __future__ import annotations

import asyncio
import contextlib
import os
import signal
from pathlib import Path
from typing import Any

from ios_decompiler_mcp.core.errors import Code, MCPError


async def run_process(argv: list[str], cwd: Path, deadline: float, *, env: dict[str, str] | None = None, output_limit: int = 1048576) -> dict[str, Any]:
    """No shell, bounded output, and process-group cleanup on timeout/cancellation."""
    try:
        process = await asyncio.create_subprocess_exec(*argv, cwd=cwd, env=env, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT, start_new_session=True)
    except OSError as exc:
        raise MCPError(Code.UNAVAILABLE, "Required executable could not start", executable=argv[0], reason=type(exc).__name__) from exc
    try:
        async with asyncio.timeout(deadline):
            chunks: list[bytes] = []
            count = 0
            assert process.stdout is not None
            while chunk := await process.stdout.read(8192):
                count += len(chunk)
                if count > output_limit:
                    raise MCPError(Code.LIMIT_EXCEEDED, "Subprocess output exceeded its limit")
                chunks.append(chunk)
            code = await process.wait()
            return {"exit_status": code, "output": b"".join(chunks).decode(errors="replace")}
    except BaseException as exc:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGTERM)
        try:
            await asyncio.wait_for(process.wait(), 2)
        except TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            await process.wait()
        if isinstance(exc, TimeoutError):
            raise MCPError(Code.TIMEOUT, "Subprocess timed out and its process group was terminated") from exc
        raise
