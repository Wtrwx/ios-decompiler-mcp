from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import Any

from vesper.adapters.classdump import ClassDumpAdapter
from vesper.adapters.debug_setup import DebugSetup
from vesper.adapters.debugger import DebuggerAdapter
from vesper.adapters.frida import FridaAdapter
from vesper.adapters.ida import IDAAdapter
from vesper.adapters.ssh import SSHAdapter
from vesper.adapters.theos import TheosAdapter
from vesper.config import Settings
from vesper.core.jobs import Jobs
from vesper.core.permissions import Permissions
from vesper.core.registry import Registry
from vesper.core.snapshots import SnapshotCache
from vesper.core.tools import ToolRegistry


class Application:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.registry = Registry(settings.state_dir)
        try:
            self.registry.acquire_server_lock()
        except BaseException:
            self.registry.close()
            raise
        self.registry.invalidate_live_sessions()
        self.permissions = Permissions(settings, self.registry)
        self.ssh = SSHAdapter(settings)
        self.frida = FridaAdapter(settings, self.registry)
        self.frida.probe = self.ssh.probe
        self.frida.on_device_lost = self.ssh.invalidate_probe
        self.ssh.on_reconnect = self.frida.device_lost
        self.snapshots = SnapshotCache(settings, self.frida.release_lease)
        self.frida.on_session_invalidated = self.snapshots.invalidate
        self.frida.on_leases_expired = self.snapshots.discard
        self.debugger = DebuggerAdapter(self)
        self.debug_setup = DebugSetup(self)
        self.classdump = ClassDumpAdapter(self)
        self.theos = TheosAdapter(settings, self.registry)
        self.ida = IDAAdapter(settings, self.registry)
        self.jobs = Jobs(self.registry, settings.max_jobs)
        self.tools = ToolRegistry(self.registry, settings.operation_timeout * 4 + 5)
        self.tools.operation_scope = self.operation_scope
        self.deployment_locks: dict[str, asyncio.Lock] = {}
        self.maintenance: asyncio.Task[None] | None = None

    def operation_scope(self, request: Any) -> contextlib.AbstractContextManager[Any]:
        device_id, bundle_id = getattr(request, "device_id", None), getattr(request, "bundle_id", None)
        session = self.frida.sessions.get(getattr(request, "session_id", ""))
        if session:
            device_id, bundle_id = session.device_id, session.bundle_id
        elif getattr(request, 'deployment_id', None):
            record = self.registry.get(request.deployment_id, 'deployment')
            device_id, bundle_id = record['device_id'], record['bundle_id']
        return self.frida.keepalive(device_id, bundle_id) if device_id and bundle_id else contextlib.nullcontext()

    def start_maintenance(self) -> None:
        if self.maintenance is not None:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return

        async def maintain() -> None:
            while True:
                await asyncio.sleep(self.settings.maintenance_interval)
                try:
                    self.snapshots.expire()
                    self.classdump.expire()
                    await self.frida.maintain()
                except Exception as exc:
                    logging.getLogger(__name__).warning("Session maintenance failed (%s)", type(exc).__name__)

        self.maintenance = loop.create_task(maintain())

    async def close(self) -> None:
        if self.maintenance:
            self.maintenance.cancel()
            await asyncio.gather(self.maintenance, return_exceptions=True)
            self.maintenance = None
        await self.jobs.close()
        self.classdump.close()
        await asyncio.gather(self.frida.close(), self.ssh.close(), self.ida.close(), return_exceptions=True)
        self.registry.close()
