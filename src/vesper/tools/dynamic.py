from __future__ import annotations

from typing import Any

from pydantic import Field

from vesper.app import Application
from vesper.tools.models import AppRequest, Empty, MethodRequest, SessionRequest


class Attach(AppRequest):
    pid: int | None = Field(default=None, ge=1)


class Events(SessionRequest):
    after: int = Field(default=0, ge=0)
    limit: int = Field(default=100, ge=1, le=500)
    hook_id: str | None = None


class Hook(MethodRequest):
    capture_arguments: bool = False
    capture_return: bool = False
    backtrace: bool = False
    max_events: int = Field(default=1000, ge=1, le=10000)


class Unhook(SessionRequest):
    hook_id: str


class EnableHook(Unhook):
    enabled: bool


def register(app: Application) -> None:
    async def devices(_: Empty) -> dict[str, Any]:
        return {"devices": await app.frida.enumerate_devices()}

    async def attach(request: Attach) -> dict[str, Any]:
        app.permissions.device(request.device_id, request.bundle_id)
        return await app.frida.attach(request.device_id, request.bundle_id, request.pid)

    async def detach(request: SessionRequest) -> dict[str, Any]:
        app.permissions.device(request.device_id)
        return await app.frida.detach(request.device_id, request.session_id)

    async def events(request: Events) -> dict[str, Any]:
        app.permissions.device(request.device_id)
        return app.frida.events(request.device_id, request.session_id, request.after, request.limit, request.hook_id)

    async def hook(request: Hook) -> dict[str, Any]:
        app.permissions.device(request.device_id)
        return await app.frida.rpc(request.device_id, request.session_id, "hook_method", request.model_dump(exclude={"device_id", "session_id"}))

    async def unhook(request: Unhook) -> dict[str, Any]:
        return await app.frida.rpc(request.device_id, request.session_id, "unhook", {"hook_id": request.hook_id})

    async def hooks(request: SessionRequest) -> dict[str, Any]:
        return await app.frida.rpc(request.device_id, request.session_id, "list_hooks")

    async def enable(request: EnableHook) -> dict[str, Any]:
        return await app.frida.rpc(request.device_id, request.session_id, "enable_hook", {"hook_id": request.hook_id, "enabled": request.enabled})

    async def export(request: Events) -> dict[str, Any]:
        result = await events(request)
        result["format"] = "json"
        result["session_id"] = request.session_id
        return result

    async def backtrace(request: Events) -> dict[str, Any]:
        result = app.frida.events(request.device_id, request.session_id, request.after, request.limit, request.hook_id)
        result["events"] = [event for event in result["events"] if "backtrace" in event]
        result["note"] = "Stacks are captured in a method's execution context. Enable backtrace when registering a hook."
        return result

    app.tools.add("frida_list_devices", Empty, devices, "Enumerate Frida transports without attaching to any application.")
    app.tools.add("frida_attach", Attach, attach, "Attach a persistent Frida session to a verified allowlisted application PID.")
    app.tools.add("frida_detach", SessionRequest, detach, "Unload the inspection agent and hooks, then detach.", read_only=False)
    app.tools.add("frida_get_events", Events, events, "Read bounded, redacted trace events by sequence cursor; includes loss count.")
    app.tools.add("frida_hook_method", Hook, hook, "Observe a method's calls without changing arguments or return values. Object contents are never dumped.", read_only=False)
    app.tools.add("frida_trace_method", Hook, hook, "Register bounded call tracing; optionally capture scalar arguments, return addresses and in-context stacks.", read_only=False)
    app.tools.add("frida_unhook", Unhook, unhook, "Remove a specific interceptor from this process session.", read_only=False)
    app.tools.add("frida_list_hooks", SessionRequest, hooks, "List this session's active interceptors and call counts.")
    app.tools.add("frida_enable_hook", EnableHook, enable, "Enable or pause an existing observation hook in this process session.", read_only=False)
    app.tools.add("frida_export_trace", Events, export, "Export one bounded JSON trace page with a continuation cursor and loss count.")
    app.tools.add("frida_get_backtrace", Events, backtrace, "Retrieve stacks captured by trace hooks in the actual method execution context.")
