from __future__ import annotations

import asyncio
import contextlib
import json
import os
import shlex
import shutil
from importlib.resources import files
from pathlib import Path
from typing import TYPE_CHECKING, Any

from vesper.core.errors import Code, MCPError
from vesper.core.registry import new_id

if TYPE_CHECKING:
    from vesper.app import Application


class DebuggerAdapter:
    def __init__(self, app: Application):
        self.app = app
        self.lldb = shutil.which('lldb')
        self.locks: dict[str, asyncio.Lock] = {}

    async def capabilities(self, device_id: str) -> dict[str, Any]:
        probe = await self.app.ssh.probe(device_id)
        path = probe.get('debugserver') or None
        return {'frida': True, 'lldb': bool(self.lldb and path), 'host_lldb': self.lldb,
                'inspection_verified': False,
                'device_debugserver': path, 'lldb_requirement': None if self.lldb and path else
                'Host lldb and an executable device debugserver are required; set devices.<id>.debugserver_path if installed elsewhere'}

    async def inspect(self, device_id: str, session_id: str, arguments: dict[str, Any]) -> dict[str, Any]:
        capabilities = await self.capabilities(device_id)
        if not capabilities['lldb']:
            raise MCPError(Code.UNAVAILABLE, 'LLDB backend is unavailable', **capabilities)
        session = self.app.frida.session(device_id, session_id)
        async with self.locks.setdefault(device_id, asyncio.Lock()), session.lock:
            self.app.frida.session(device_id, session_id)
            return await self._inspect(device_id, session_id, arguments, capabilities)

    async def _inspect(self, device_id: str, session_id: str, arguments: dict[str, Any], capabilities: dict[str, Any]) -> dict[str, Any]:
        session = self.app.frida.session(device_id, session_id)
        connection = await self.app.ssh.connect(device_id)
        port = self.app.settings.devices[device_id].debugserver_port
        remote: Any = None
        listener = local = None
        readers: list[asyncio.Task[None]] = []
        request_file: Path | None = None
        output: list[str] = []
        ready, exited = asyncio.Event(), asyncio.Event()

        async def read_remote(stream: Any) -> None:
            while line := await stream.readline():
                if isinstance(line, bytes):
                    line = line.decode('utf-8', errors='replace')
                if sum(map(len, output)) < 8192:
                    output.append(line[:1024])
                if 'listening' in line.lower() or 'waiting for' in line.lower():
                    ready.set()

        async def wait_remote() -> None:
            await remote.wait_closed()
            exited.set()

        try:
            # Debugserver binds loopback. SSH carries the GDB remote protocol;
            # no device debugger port is exposed to the surrounding network.
            command = f"{shlex.quote(capabilities['device_debugserver'])} 127.0.0.1:{port} --attach={session.pid}"
            remote = await connection.create_process(command, term_type='dumb')
            readers = [asyncio.create_task(read_remote(remote.stdout)), asyncio.create_task(read_remote(remote.stderr)), asyncio.create_task(wait_remote())]
            ready_task, exit_task = asyncio.create_task(ready.wait()), asyncio.create_task(exited.wait())
            try:
                done, _ = await asyncio.wait([ready_task, exit_task], timeout=min(10, self.app.settings.operation_timeout), return_when=asyncio.FIRST_COMPLETED)
                if not done or not ready.is_set():
                    raise MCPError(Code.UNAVAILABLE, 'Device debugserver did not become ready', diagnostic=''.join(output)[-1024:], exit_status=remote.exit_status, exit_signal=remote.exit_signal)
            finally:
                ready_task.cancel()
                exit_task.cancel()
                await asyncio.gather(ready_task, exit_task, return_exceptions=True)
            listener = await connection.forward_local_port('127.0.0.1', 0, '127.0.0.1', port)
            request_file = self.app.settings.state_dir / (new_id('lldb') + '.json')
            with request_file.open('x', encoding='utf-8') as stream:
                request_file.chmod(0o600)
                json.dump({**arguments, 'pid': session.pid, 'url': f'connect://127.0.0.1:{listener.get_port()}'}, stream)
            worker = files('vesper').joinpath('assets/lldb_worker.py')
            environment = {**os.environ, 'VESPER_LLDB_REQUEST': str(request_file)}
            local = await asyncio.create_subprocess_exec(str(capabilities['host_lldb']), '--no-lldbinit', '--batch',
                '-o', 'command script import ' + shlex.quote(str(worker)),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=environment)
            stdout, stderr = await self._output(local)
            for line in stdout.splitlines():
                if line.startswith('IOS_DEBUG_JSON:'):
                    result: dict[str, Any] = json.loads(line.removeprefix('IOS_DEBUG_JSON:'))
                    if result.get('error'):
                        raise MCPError(Code.UNAVAILABLE, 'LLDB inspection failed', diagnostic=result['error'], detached=result.get('detached'))
                    if not result.get('detached'):
                        raise MCPError(Code.UNAVAILABLE, 'LLDB could not confirm debugger detach', **result)
                    return result
            raise MCPError(Code.UNAVAILABLE, 'LLDB did not return inspection data', diagnostic=stderr[-1024:])
        finally:
            if local is not None and local.returncode is None:
                local.kill()
                await local.wait()
            if listener is not None:
                listener.close()
                await listener.wait_closed()
            if remote is not None:
                # Closing only this request's server also drops its debug task.
                remote.terminate()
                remote.close()
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(remote.wait_closed(), 2)
                # A killed/failed debugger must never leave our still-attached
                # target stopped. A detached/exited Frida handle is not reused.
                if session.active and not getattr(session.handle, 'is_detached', False):
                    with contextlib.suppress(Exception):
                        await self.app.ssh._run(device_id, f'kill -CONT {session.pid}', timeout=2)
            for reader in readers:
                reader.cancel()
            await asyncio.gather(*readers, return_exceptions=True)
            if request_file is not None:
                request_file.unlink(missing_ok=True)

    async def _output(self, process: Any) -> tuple[str, str]:
        async def read(stream: Any) -> str:
            chunks: list[bytes] = []
            size = 0
            while chunk := await stream.read(8192):
                size += len(chunk)
                if size > 262144:
                    raise MCPError(Code.LIMIT_EXCEEDED, 'LLDB output exceeded 256 KiB')
                chunks.append(chunk)
            return b''.join(chunks).decode('utf-8', errors='replace')
        try:
            async with asyncio.timeout(self.app.settings.operation_timeout):
                readers = [asyncio.create_task(read(process.stdout)), asyncio.create_task(read(process.stderr))]
                try:
                    stdout, stderr = await asyncio.gather(*readers)
                    await process.wait()
                    return stdout, stderr
                finally:
                    for reader in readers:
                        reader.cancel()
                    await asyncio.gather(*readers, return_exceptions=True)
        except TimeoutError as exc:
            raise MCPError(Code.TIMEOUT, 'LLDB inspection timed out') from exc
