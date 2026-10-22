from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import Field

from vesper.app import Application
from vesper.core.errors import Code, MCPError
from vesper.tools.models import AppRequest


class Logs(AppRequest):
    action: Literal['read', 'start', 'stop'] = 'read'
    after: int = Field(default=0, ge=0)
    limit: int = Field(default=20, ge=1, le=100)
    wait_ms: int = Field(default=0, ge=0, le=2000)
    contains: str | None = Field(default=None, min_length=1, max_length=255)
    level: Literal['default', 'info', 'debug', 'error', 'fault'] | None = None
    sources: list[Literal['os_log', 'nslog', 'stdio']] = Field(default=['os_log'], min_length=1, max_length=3)
    capacity: int = Field(default=200, ge=1, le=1000)
    max_message_length: int = Field(default=512, ge=32, le=2048)


class Inspect(AppRequest):
    mode: Literal['capabilities', 'threads', 'backtrace', 'registers', 'locals'] = 'backtrace'
    backend: Literal['frida', 'lldb'] = 'frida'
    thread_id: int | None = Field(default=None, ge=1)
    max_threads: int = Field(default=3, ge=1, le=16)
    max_frames: int = Field(default=8, ge=1, le=32)
    symbols: bool = True
    register_names: list[Annotated[str, Field(max_length=16, pattern=r'^[A-Za-z][A-Za-z0-9_]*$')]] = Field(default=[], max_length=32)
    frame_index: int = Field(default=0, ge=0, le=31)
    max_variables: int = Field(default=10, ge=1, le=32)


class Setup(AppRequest):
    action: Literal['check', 'install', 'repair'] = 'check'
    local_debugserver_path: Path | None = None


def register(app: Application) -> None:
    async def setup(request: Setup) -> dict[str, Any]:
        app.permissions.device(request.device_id, request.bundle_id)
        if request.action == 'check':
            return await app.debug_setup.check(request.device_id, request.bundle_id)
        return await app.debug_setup.install(request.device_id, request.bundle_id, request.local_debugserver_path,
                                            repair=request.action == 'repair')

    async def logs(request: Logs) -> dict[str, Any]:
        app.permissions.device(request.device_id, request.bundle_id)
        if request.action == 'stop' and not any(session.active and session.device_id == request.device_id and
                session.bundle_id == request.bundle_id and not getattr(session.handle, 'is_detached', False)
                for session in app.frida.sessions.values()):
            return {'active': False, 'stopped': True}
        attached = await app.frida.attach(request.device_id, request.bundle_id)
        result = await app.frida.rpc(request.device_id, attached['session_id'], 'app_logs',
                                     request.model_dump(exclude={'device_id', 'bundle_id'}))
        return {'session_id': attached['session_id'], 'reused': attached.get('reused', False), **result}

    async def inspect(request: Inspect) -> dict[str, Any]:
        app.permissions.device(request.device_id, request.bundle_id)
        if request.mode == 'capabilities':
            return await app.debugger.capabilities(request.device_id)
        if request.mode == 'locals' and request.backend != 'lldb':
            raise MCPError(Code.INVALID_INPUT, 'Local variables require backend=lldb and device debugserver')
        attached = await app.frida.attach(request.device_id, request.bundle_id)
        arguments = request.model_dump(exclude={'device_id', 'bundle_id', 'backend'})
        if request.backend == 'lldb':
            result = await app.debugger.inspect(request.device_id, attached['session_id'], arguments)
        else:
            result = await app.frida.rpc(request.device_id, attached['session_id'], 'debug_inspect', arguments)
        return {'session_id': attached['session_id'], 'reused': attached.get('reused', False), **result}

    app.tools.add('app_logs', Logs, logs,
        'Start/reuse app log hooks and read one filtered page from a bounded on-device ring. '
        'Pass after=next_cursor; default 20 entries, no waiting. os_log/NSLog expose format strings; '
        'NSLogv and stdio expose rendered text. Sources/buffer options apply when starting. '
        'Stop removes hooks; an active log stream keeps the session alive.', read_only=False)
    app.tools.add('debug_inspect', Inspect, inspect,
        'Inspect app threads, bounded backtraces or registers in one call. Frida is immediate and '
        'samples running threads. backend=lldb temporarily stops the process, supports locals, then '
        'detaches/resumes. mode=capabilities checks host LLDB and cached device debugserver availability. '
        'No arbitrary debugger commands or expression execution.')
    app.tools.add('debug_setup', Setup, setup,
        'Check required Frida/LLDB/debugserver components and return actionable missing-component instructions. '
        'action=install installs absent device debugserver from the matching local Xcode iOS image or a workspace '
        'local_debugserver_path. action=repair reapplies an existing device-provided signing profile. '
        'Installation checks execution; verify actual attach separately with debug_inspect(backend=lldb).', read_only=False)
