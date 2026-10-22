from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import Field

from vesper.app import Application
from vesper.core.permissions import sha256
from vesper.core.registry import new_id
from vesper.tools.models import AppRequest, DeviceRequest, Empty


class Upload(DeviceRequest):
    local_path: Path
    remote_path: str = Field(min_length=1, max_length=4096)
    approval_id: str | None = None


class Download(DeviceRequest):
    remote_path: str = Field(min_length=1, max_length=4096)
    local_path: Path


class MutateApp(AppRequest):
    approval_id: str | None = None


class DeviceInfo(DeviceRequest):
    force_refresh: bool = False


def register(app: Application) -> None:
    async def configured(_: Empty) -> dict[str, Any]:
        return {"devices": [{"device_id": key, "allowed_apps": device.allowed_apps, "frida_configured": bool(device.frida_device_id or device.frida_remote)} for key, device in app.settings.devices.items()]}

    async def connect(request: DeviceRequest) -> dict[str, Any]:
        app.permissions.device(request.device_id)
        info = await app.ssh.probe(request.device_id)
        session_id = new_id("device")
        app.registry.save(session_id, "device_session", {"device_id": request.device_id, "info": info})
        return {"device_session_id": session_id, **info}

    async def info(request: DeviceInfo) -> dict[str, Any]:
        app.permissions.device(request.device_id)
        if request.force_refresh:
            return await app.ssh.probe(request.device_id, force=True)
        return await app.ssh.probe(request.device_id)

    async def apps(request: DeviceRequest) -> dict[str, Any]:
        app.permissions.device(request.device_id)
        return {"applications": await app.frida.applications(request.device_id)}

    async def processes(request: DeviceRequest) -> dict[str, Any]:
        app.permissions.device(request.device_id)
        return {"processes": await app.frida.processes(request.device_id)}

    async def upload(request: Upload) -> dict[str, Any]:
        app.permissions.device(request.device_id)
        local = app.permissions.local_path(request.local_path, must_exist=True)
        app.ssh._remote_within(request.remote_path, [app.settings.devices[request.device_id].staging_directory])
        digest = sha256(local)
        app.permissions.require("device_upload", {"device_id": request.device_id, "remote_path": request.remote_path, "sha256": digest}, request.approval_id)
        return await app.ssh.upload(request.device_id, local, request.remote_path, expected_sha256=digest)

    async def download(request: Download) -> dict[str, Any]:
        app.permissions.device(request.device_id)
        local = app.permissions.download_path(request.local_path)
        return await app.ssh.download(request.device_id, request.remote_path, local)

    async def launch(request: MutateApp) -> dict[str, Any]:
        app.permissions.device(request.device_id, request.bundle_id)
        app.permissions.require("device_launch", {"device_id": request.device_id, "bundle_id": request.bundle_id}, request.approval_id)
        return await app.frida.spawn(request.device_id, request.bundle_id)

    async def terminate(request: MutateApp) -> dict[str, Any]:
        app.permissions.device(request.device_id, request.bundle_id)
        app.permissions.require("device_terminate", {"device_id": request.device_id, "bundle_id": request.bundle_id}, request.approval_id)
        return await app.frida.terminate(request.device_id, request.bundle_id)

    app.tools.add("device_list", Empty, configured, "List configured allowlisted device IDs and applications.")
    app.tools.add("device_connect", DeviceRequest, connect, "Connect using pinned SSH host keys and public-key authentication; discover iOS and jailbreak environment.")
    app.tools.add("device_info", DeviceInfo, info, "Get TTL-cached SSH discovery for this connection; force_refresh=true requests fresh architecture, iOS and jailbreak evidence.")
    app.tools.add("device_list_apps", DeviceRequest, apps, "Discover allowlisted installed applications, bundle paths and running PIDs via Frida.")
    app.tools.add("device_list_processes", DeviceRequest, processes, "Enumerate running processes of allowlisted applications.")
    app.tools.add("device_upload", Upload, upload, "Upload a workspace artifact to the configured staging directory with an exact-content operator approval.", read_only=False)
    app.tools.add("device_download", Download, download, "Download a bounded file from configured device read roots into the workspace.")
    app.tools.add("device_launch", MutateApp, launch, "Launch an explicitly selected app using Frida spawn/resume. Requires operator approval.", read_only=False)
    app.tools.add("device_terminate", MutateApp, terminate, "Terminate the selected app after explicit operator approval.", read_only=False)
