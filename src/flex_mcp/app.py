from __future__ import annotations

import asyncio

from flex_mcp.adapters.frida import FridaAdapter
from flex_mcp.adapters.ida import IDAAdapter
from flex_mcp.adapters.ssh import SSHAdapter
from flex_mcp.adapters.theos import TheosAdapter
from flex_mcp.config import Settings
from flex_mcp.core.jobs import Jobs
from flex_mcp.core.permissions import Permissions
from flex_mcp.core.registry import Registry
from flex_mcp.core.tools import ToolRegistry


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
        self.theos = TheosAdapter(settings, self.registry)
        self.ida = IDAAdapter(settings, self.registry)
        self.jobs = Jobs(self.registry, settings.max_jobs)
        self.tools = ToolRegistry(self.registry, settings.operation_timeout * 4 + 5)
        self.deployment_locks: dict[str, asyncio.Lock] = {}

    async def close(self) -> None:
        await self.jobs.close()
        await asyncio.gather(self.frida.close(), self.ssh.close(), self.ida.close(), return_exceptions=True)
        self.registry.close()
