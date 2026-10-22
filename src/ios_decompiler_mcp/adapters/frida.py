from __future__ import annotations

import asyncio
import contextlib
import importlib
import json
from collections.abc import Callable
from importlib.resources import files
from typing import Any

from ios_decompiler_mcp.config import Settings
from ios_decompiler_mcp.core.errors import Code, MCPError
from ios_decompiler_mcp.core.registry import Registry, new_id
from ios_decompiler_mcp.core.sessions import ProcessSession, require_session


class FridaAdapter:
    def __init__(self, settings: Settings, registry: Registry, api: Any = None):
        self.settings, self.registry, self._api = settings, registry, api
        self.devices: dict[str, Any] = {}
        self.sessions: dict[str, ProcessSession] = {}
        self.slots = asyncio.Semaphore(4)
        self.workers: set[asyncio.Task[Any]] = set()
        self.attach_lock = asyncio.Lock()
        self.closing = False

    @property
    def api(self) -> Any:
        if self._api is None:
            try:
                self._api = importlib.import_module("frida")
            except ImportError as exc:
                raise MCPError(Code.UNAVAILABLE, "Install ios-decompiler-mcp[device] to enable Frida") from exc
        return self._api

    async def _call(self, fn: Callable[[], Any], *, late_cleanup: Callable[[Any], None] | None = None) -> Any:
        try:
            await asyncio.wait_for(self.slots.acquire(), self.settings.operation_timeout)
        except TimeoutError as exc:
            raise MCPError(Code.LIMIT_EXCEEDED, "Frida workers are busy") from exc
        try:
            cancellable = self.api.Cancellable()
        except BaseException:
            self.slots.release()
            raise

        def work() -> Any:
            with cancellable:
                return fn()

        task = asyncio.create_task(asyncio.to_thread(work))
        self.workers.add(task)
        def finished(done: asyncio.Task[Any]) -> None:
            self.slots.release()
            self.workers.discard(done)
        task.add_done_callback(finished)
        try:
            return await asyncio.wait_for(asyncio.shield(task), self.settings.operation_timeout)
        except (TimeoutError, asyncio.CancelledError) as exc:
            cancellable.cancel()

            def discard(done: asyncio.Task[Any]) -> None:
                with contextlib.suppress(Exception, asyncio.CancelledError):
                    value = done.result()
                    if late_cleanup is not None:
                        # Cleanup may block; never execute it on the event-loop callback thread.
                        asyncio.get_running_loop().run_in_executor(None, late_cleanup, value)

            task.add_done_callback(discard)
            if isinstance(exc, asyncio.CancelledError):
                raise
            raise MCPError(Code.TIMEOUT, "Frida operation timed out; process sessions may need reattachment", retryable=True) from exc
        except MCPError:
            raise
        except Exception as exc:
            raise MCPError(Code.FRIDA_ERROR, "Frida operation failed", reason=type(exc).__name__, diagnostic=str(exc)[:500], retryable=True) from exc

    async def enumerate_devices(self) -> list[dict[str, Any]]:
        devices = await self._call(lambda: self.api.get_device_manager().enumerate_devices())
        return [{"id": device.id, "name": device.name, "type": device.type} for device in devices]

    async def device(self, device_id: str) -> Any:
        if device_id not in self.settings.devices:
            raise MCPError(Code.NOT_ALLOWED, "Device is not allowlisted")
        if device_id in self.devices:
            return self.devices[device_id]
        config = self.settings.devices[device_id]
        if config.frida_remote:
            device = await self._call(lambda: self.api.get_device_manager().add_remote_device(config.frida_remote))
        elif config.frida_device_id:
            device = await self._call(lambda: self.api.get_device(config.frida_device_id, timeout=int(self.settings.operation_timeout)))
        else:
            raise MCPError(Code.INVALID_INPUT, "Configure frida_device_id or frida_remote explicitly; use frida_list_devices for discovery")
        self.devices[device_id] = device
        return device

    async def applications(self, device_id: str) -> list[dict[str, Any]]:
        device = await self.device(device_id)
        allowed = self.settings.devices[device_id].allowed_apps
        if not allowed:
            return []
        apps = await self._call(lambda: device.enumerate_applications(identifiers=allowed, scope="full"))
        return [{"bundle_id": app.identifier, "name": app.name, "pid": app.pid, "parameters": {k: v for k, v in app.parameters.items() if k in {"path", "version", "build", "containers"}}} for app in apps if app.identifier in allowed]

    async def processes(self, device_id: str) -> list[dict[str, Any]]:
        # Only return processes belonging to an explicitly allowed application.
        return [{"pid": app["pid"], "bundle_id": app["bundle_id"], "name": app["name"]} for app in await self.applications(device_id) if app["pid"]]

    def compatibility(self, device_id: str, observed_server_version: str | None = None) -> dict[str, Any]:
        host = self.api.__version__
        server = observed_server_version or self.settings.devices[device_id].frida_server_version
        if server and server.split(".")[0] != host.split(".")[0]:
            raise MCPError(Code.FRIDA_ERROR, "Frida host/server major versions differ", host_version=host, server_version=server)
        return {"host_version": host, "server_version": server, "verified": server == host if server else False, "warning": None if server == host else "Use identical host/server versions; exact compatibility is unverified"}

    async def attach(self, device_id: str, bundle_id: str, pid: int | None = None, *, server_version: str | None = None) -> dict[str, Any]:
        async with self.attach_lock:
            if self.closing:
                raise MCPError(Code.SESSION_INVALID, "Frida manager is closing")
            return await self._attach(device_id, bundle_id, pid, server_version=server_version)

    async def _attach(self, device_id: str, bundle_id: str, pid: int | None = None, *, server_version: str | None = None) -> dict[str, Any]:
        config = self.settings.devices.get(device_id)
        if config is None or bundle_id not in config.allowed_apps:
            raise MCPError(Code.NOT_ALLOWED, "Device/application pair is not allowlisted")
        for session in self.sessions.values():
            if session.active and session.device_id == device_id and session.bundle_id == bundle_id:
                if pid is not None and pid != session.pid:
                    raise MCPError(Code.SESSION_INVALID, "Close the previous process session before attaching a different PID")
                return session.metadata()
        if sum(session.active for session in self.sessions.values()) >= self.settings.max_sessions:
            raise MCPError(Code.LIMIT_EXCEEDED, "Too many attached process sessions")
        # Keep a bounded history for post-exit event retrieval.
        stale = [key for key, value in self.sessions.items() if not value.active]
        for key in stale[:-self.settings.max_sessions]:
            self.sessions.pop(key, None)
        compatibility = self.compatibility(device_id, server_version)
        apps = await self.applications(device_id)
        app = next((app for app in apps if app["bundle_id"] == bundle_id), None)
        if not app or not app["pid"]:
            raise MCPError(Code.NOT_FOUND, "Selected application is not running; launch it explicitly")
        if pid is not None and pid != app["pid"]:
            raise MCPError(Code.IDENTITY_MISMATCH, "PID does not match the selected application's observed process")
        pid = app["pid"]
        agent_path = files("ios_decompiler_mcp").joinpath("assets/agent.js")
        if not agent_path.is_file():
            raise MCPError(Code.UNAVAILABLE, "Frida agent bundle is missing; run npm ci && npm run build")
        source = agent_path.read_text()
        device = await self.device(device_id)
        try:
            handle = await self._call(lambda: device.attach(pid), late_cleanup=lambda value: value.detach())
        except MCPError as exc:
            exc.details["phase"] = "process_attach"
            raise
        session_id = new_id("process")
        session = ProcessSession(session_id, device_id, bundle_id, pid, handle)
        self.sessions[session_id] = session
        loop = asyncio.get_running_loop()

        def detached(reason: str, crash: Any = None) -> None:
            def invalidate() -> None:
                session.invalidate(str(reason), self.registry)
                session.event({"type": "detached", "reason": str(reason), "crashed": crash is not None}, self.settings.event_limit)
                self.devices.pop(device_id, None)
            if not self.closing and not loop.is_closed():
                loop.call_soon_threadsafe(invalidate)

        handle.on("detached", detached)
        phase = "script_create"
        try:
            script = await self._call(lambda: handle.create_script(source, name="ios-decompiler-mcp"), late_cleanup=lambda value: value.unload())
            session.script = script

            def message_received(message: dict[str, Any], data: bytes | None = None) -> None:
                if message.get("type") == "send" and isinstance(message.get("payload"), dict):
                    payload = message["payload"]
                elif message.get("type") == "error":
                    payload = {"type": "agent_error", "message": str(message.get("description", "Agent error"))[:1000]}
                else:
                    return
                if len(json.dumps(payload, default=str)) <= 32768 and not loop.is_closed():
                    loop.call_soon_threadsafe(session.event, payload, self.settings.event_limit)

            script.on("message", message_received)
            phase = "script_load"
            await self._call(script.load)
            phase = "agent_initialize"
            identity = await self._call(lambda: script.exports_sync.dispatch("initialize", {"session_id": session_id, "bundle_id": bundle_id}))
            if identity.get("agent_error"):
                raise MCPError(Code.FRIDA_ERROR, identity["agent_error"], agent_code=identity.get("code"))
            if identity.get("bundle_id") != bundle_id or identity.get("pid") != pid:
                raise MCPError(Code.IDENTITY_MISMATCH, "Injected process identity does not match selected application")
            self.registry.save(session_id, "process_session", session.metadata())
            return {**session.metadata(), "identity": identity, "compatibility": compatibility}
        except BaseException as exc:
            if isinstance(exc, MCPError):
                exc.details["phase"] = phase
            await self.detach(device_id, session_id)
            raise

    def session(self, device_id: str, session_id: str) -> ProcessSession:
        return require_session(self.sessions, device_id, session_id)

    async def rpc(self, device_id: str, session_id: str, method: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        session = self.session(device_id, session_id)
        async with session.lock:
            self.session(device_id, session_id)
            try:
                result = await self._call(lambda: session.script.exports_sync.dispatch(method, arguments or {}))
                self.session(device_id, session_id)
                if isinstance(result, dict) and result.get("agent_error"):
                    raise MCPError(Code.INVALID_INPUT, result["agent_error"], agent_code=result.get("code"))
                return result if isinstance(result, dict) else {"items": result}
            except MCPError as exc:
                if exc.code in (Code.TIMEOUT, Code.FRIDA_ERROR):
                    session.invalidate(exc.code, self.registry)
                    await self.detach(device_id, session_id)
                raise
            except asyncio.CancelledError:
                session.invalidate("cancelled_rpc", self.registry)
                await asyncio.shield(self.detach(device_id, session_id))
                raise

    def events(self, device_id: str, session_id: str, after: int = 0, limit: int = 100, hook_id: str | None = None) -> dict[str, Any]:
        session = self.sessions.get(session_id)
        if session is None or session.device_id != device_id:
            raise MCPError(Code.SESSION_INVALID, "Unknown process session")
        values = [event for event in session.events if event["sequence"] > after and (hook_id is None or event.get("hook_id") == hook_id)][:limit]
        return {"events": values, "next_sequence": values[-1]["sequence"] if values else after, "dropped": session.dropped, "active": session.active}

    async def spawn(self, device_id: str, bundle_id: str) -> dict[str, Any]:
        device = await self.device(device_id)
        pid = await self._call(lambda: device.spawn([bundle_id]), late_cleanup=lambda value: device.kill(value))
        try:
            await self._call(lambda: device.resume(pid))
        except BaseException:
            with contextlib.suppress(Exception):
                await self._call(lambda: device.kill(pid))
            raise
        return {"pid": pid, "bundle_id": bundle_id, "launched": True}

    async def terminate(self, device_id: str, bundle_id: str) -> dict[str, Any]:
        app = next((app for app in await self.applications(device_id) if app["bundle_id"] == bundle_id), None)
        if not app or not app["pid"]:
            return {"terminated": False, "reason": "not_running"}
        device = await self.device(device_id)
        await self._call(lambda: device.kill(app["pid"]))
        for session in self.sessions.values():
            if session.device_id == device_id and session.pid == app["pid"]:
                session.invalidate("terminated", self.registry)
        return {"terminated": True, "pid": app["pid"]}

    async def detach(self, device_id: str, session_id: str) -> dict[str, Any]:
        session = self.sessions.get(session_id)
        if session is None or session.device_id != device_id:
            raise MCPError(Code.SESSION_INVALID, "Unknown process session")
        session.invalidate("closed", self.registry)
        if session.script is not None:
            with contextlib.suppress(Exception):
                await self._call(lambda: session.script.exports_sync.dispatch("dispose", {}))
            with contextlib.suppress(Exception):
                await self._call(session.script.unload)
            session.script = None
        with contextlib.suppress(Exception):
            await self._call(session.handle.detach)
        return {"session_id": session_id, "closed": True}

    async def close(self) -> None:
        self.closing = True
        await asyncio.gather(*(self.detach(s.device_id, s.id) for s in list(self.sessions.values())), return_exceptions=True)
        self.devices.clear()
