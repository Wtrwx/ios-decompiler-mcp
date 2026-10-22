from __future__ import annotations

import asyncio
import contextlib
import json
import os
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from vesper.adapters.macho import inspect_macho
from vesper.config import Settings
from vesper.core.errors import Code, MCPError
from vesper.core.permissions import sha256
from vesper.core.registry import Registry, new_id


@dataclass
class IDASession:
    id: str
    process: asyncio.subprocess.Process
    metadata: dict[str, Any]
    macho: dict[str, Any] | None
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    stderr: asyncio.Task[None] | None = None
    diagnostic: str = ""
    active: bool = True


class IDAAdapter:
    def __init__(self, settings: Settings, registry: Registry):
        self.settings, self.registry = settings, registry
        self.sessions: dict[str, IDASession] = {}

    def installation(self) -> Path:
        if self.settings.ida_directory:
            return self.settings.ida_directory.expanduser().resolve()
        if os.environ.get("IDADIR"):
            return Path(os.environ["IDADIR"]).expanduser().resolve()
        candidates = list(Path("/Applications").glob("IDA Professional *.app/Contents/MacOS"))
        if len(candidates) == 1:
            return candidates[0]
        raise MCPError(Code.UNAVAILABLE, "Configure ida_directory for an installed, licensed IDA Pro 9+ SDK; server inspection tools do not require IDA")

    async def open(self, path: Path, architecture: str | None = None, binary_path: Path | None = None) -> dict[str, Any]:
        root = self.installation()
        if not (root / "idalib/python/idapro").is_dir():
            raise MCPError(Code.UNAVAILABLE, "Official idapro package is absent from the configured IDA installation")
        if sum(session.active for session in self.sessions.values()) >= min(4, self.settings.max_sessions):
            raise MCPError(Code.LIMIT_EXCEEDED, "IDA worker capacity reached")
        for key in [key for key, value in self.sessions.items() if not value.active]:
            self.sessions.pop(key, None)
        session_id = new_id("ida")
        directory = self.settings.state_dir / "ida" / session_id
        directory.mkdir(parents=True)
        copied = directory / path.name
        metadata: dict[str, Any] | None = None
        source_digest: str | None = None
        if path.suffix.lower() in {".i64", ".idb"}:
            shutil.copyfile(path, copied)
            if binary_path:
                metadata = await asyncio.to_thread(inspect_macho, binary_path, architecture)
                source_digest = sha256(binary_path)
        else:
            metadata = await asyncio.to_thread(inspect_macho, path, architecture, copied)
            source_digest = sha256(copied)
        environment = {**os.environ, "IDADIR": str(root), "PYTHONPATH": str(Path(__file__).resolve().parents[2]) + os.pathsep + os.environ.get("PYTHONPATH", "")}
        python = str(self.settings.ida_python or sys.executable)
        process = await asyncio.create_subprocess_exec(python, "-u", "-m", "vesper.adapters.ida_worker", "--ida-directory", str(root), "--database", str(copied), cwd=directory, env=environment, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, limit=1048576)
        session = IDASession(session_id, process, {}, metadata)
        self.sessions[session_id] = session

        async def drain() -> None:
            assert process.stderr is not None
            while chunk := await process.stderr.read(4096):
                session.diagnostic = (session.diagnostic + chunk.decode(errors="replace"))[-16384:]
        session.stderr = asyncio.create_task(drain())
        try:
            assert process.stdout is not None
            async with asyncio.timeout(self.settings.build_timeout):
                line = await process.stdout.readline()
                response = json.loads(line)
            if not response.get("ready"):
                raise MCPError(Code.UNAVAILABLE, "IDA worker could not initialize", diagnostic=response.get("error", {}))
            session.metadata = response["metadata"]
            if metadata is not None:
                if not source_digest or session.metadata.get("input_sha256") != source_digest:
                    raise MCPError(Code.IDENTITY_MISMATCH, "IDA input SHA-256 differs from the Mach-O used for UUID/segment metadata")
                metadata["database_identity_verified"] = True
            self.registry.save(session_id, "ida_session", {"path": str(copied), "metadata": session.metadata, "macho": metadata})
            return {"ida_session_id": session_id, "metadata": session.metadata, "macho": metadata, "database_copy": str(copied)}
        except BaseException as exc:
            await self.close_session(session_id)
            if isinstance(exc, TimeoutError):
                raise MCPError(Code.TIMEOUT, "IDA analysis timed out and its worker was terminated") from exc
            if isinstance(exc, (json.JSONDecodeError, ValueError)):
                raise MCPError(Code.IDA_ERROR, "IDA worker terminated without a valid readiness response", returncode=process.returncode, diagnostic=session.diagnostic[-1000:]) from exc
            raise

    def session(self, session_id: str) -> IDASession:
        session = self.sessions.get(session_id)
        if session is None or not session.active or session.process.returncode is not None:
            raise MCPError(Code.SESSION_INVALID, "IDA session is unavailable; reopen its database")
        return session

    async def rpc(self, session_id: str, operation: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        session = self.session(session_id)
        async with session.lock:
            request_id = new_id("ida_request")
            process = session.process
            assert process.stdin is not None and process.stdout is not None
            try:
                async with asyncio.timeout(self.settings.operation_timeout):
                    process.stdin.write((json.dumps({"id": request_id, "operation": operation, "arguments": arguments or {}}) + "\n").encode())
                    await process.stdin.drain()
                    response = json.loads(await process.stdout.readline())
                if response.get("id") != request_id:
                    await self.close_session(session_id)
                    raise MCPError(Code.IDA_ERROR, "IDA worker response identifier did not match")
                if "error" in response:
                    raise MCPError(Code.IDA_ERROR, "IDA query could not complete", diagnostic=response["error"])
                return response["result"]
            except (TimeoutError, asyncio.CancelledError, BrokenPipeError, json.JSONDecodeError) as exc:
                await self.close_session(session_id)
                if isinstance(exc, asyncio.CancelledError):
                    raise
                raise MCPError(Code.TIMEOUT if isinstance(exc, TimeoutError) else Code.IDA_ERROR, "IDA worker failed and was invalidated") from exc

    async def close_session(self, session_id: str) -> dict[str, Any]:
        session = self.sessions.get(session_id)
        if session is None:
            raise MCPError(Code.SESSION_INVALID, "Unknown IDA session")
        session.active = False
        if session.process.returncode is None:
            if session.process.stdin is not None:
                with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                    session.process.stdin.write((json.dumps({"id": "close", "operation": "close"}) + "\n").encode())
                    await session.process.stdin.drain()
            try:
                await asyncio.wait_for(session.process.wait(), 3)
            except TimeoutError:
                session.process.terminate()
                try:
                    await asyncio.wait_for(session.process.wait(), 2)
                except TimeoutError:
                    session.process.kill()
                    await session.process.wait()
        if session.stderr:
            await session.stderr
        self.registry.save(session_id, "ida_session", {"metadata": session.metadata}, "closed")
        return {"ida_session_id": session_id, "closed": True}

    async def close(self) -> None:
        await asyncio.gather(*(self.close_session(session_id) for session_id in self.sessions), return_exceptions=True)
