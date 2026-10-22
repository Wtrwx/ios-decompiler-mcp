"""External-boundary fakes only. Nothing in the production package imports these."""
from __future__ import annotations

import hashlib
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from vesper.adapters.debian import inspect_package
from vesper.app import Application
from vesper.core.sessions import ProcessSession, require_session


class FakeSSH:
    def __init__(self, app: Application):
        self.app = app
        self.files: dict[str, bytes] = {}
        self.installed: dict[str, Any] | None = None
        self.mutations: list[str] = []
        self.fail_install = False

    async def probe(self, device_id):
        return {"device_id": device_id, "architecture": "arm64", "ios_version": "16.5", "mode": "rootless", "prefix": "/var/jb", "frida_version": "17.24.3"}

    async def package_status(self, device_id, package_id):
        return {"installed": self.installed is not None, "version": self.installed["metadata"]["version"] if self.installed else None}

    async def upload(self, device_id, local, remote):
        self.mutations.append("upload")
        self.files[remote] = Path(local).read_bytes()
        return {"remote_path": remote}

    async def file_sha256(self, device_id, path):
        if path in self.files:
            return hashlib.sha256(self.files[path]).hexdigest()
        if self.installed and path == self.installed["metadata"]["dylib_path"]:
            return self.installed["metadata"]["dylib_sha256"]
        return "not-installed"

    async def install(self, device_id, remote):
        self.mutations.append("install")
        if self.fail_install:
            return {"exit_status": 1, "stderr": "simulated dpkg failure", "stdout": ""}
        digest = hashlib.sha256(self.files[remote]).hexdigest()
        build = next(item for item in self.app.registry.list("build") if item.get("package_sha256") == digest)
        metadata = inspect_package(Path(build["package_path"]), build["spec"], self.app.settings.max_transfer_bytes)
        self.installed = {"build": build, "metadata": metadata}
        return {"exit_status": 0, "stdout": "installed", "stderr": ""}

    async def uninstall(self, device_id, package_id):
        self.mutations.append("uninstall")
        self.installed = None
        return {"exit_status": 0, "stdout": "removed", "stderr": ""}

    async def list_crashes(self, device_id, executable, since):
        return []

    async def close(self):
        pass


class FakeFrida:
    def __init__(self, app: Application, ssh: FakeSSH):
        self.app, self.ssh = app, ssh
        self.sessions: dict[str, ProcessSession] = {}
        self.pid = 42
        self.loaded: dict[str, Any] | None = None
        self.title = "Original"
        self.wrong_title = False

    def keepalive(self, *args):
        return nullcontext()

    async def applications(self, device_id):
        return [{"bundle_id": "dev.iosdecompiler.fixture", "name": "Fixture", "pid": self.pid, "parameters": {"path": "/Applications/DecompilerFixture.app"}}]

    async def attach(self, device_id, bundle_id, pid=None, **kwargs):
        for session in self.sessions.values():
            if session.active:
                return session.metadata()
        session_id = f"process_{self.pid}"
        session = ProcessSession(session_id, device_id, bundle_id, self.pid, SimpleNamespace())
        self.sessions[session_id] = session
        return session.metadata()

    def session(self, device_id, session_id):
        return require_session(self.sessions, device_id, session_id)

    async def detach(self, device_id, session_id):
        self.sessions[session_id].invalidate("closed", self.app.registry)

    async def terminate(self, device_id, bundle_id):
        self.ssh.mutations.append("terminate")
        self.loaded = None

    async def spawn(self, device_id, bundle_id):
        self.ssh.mutations.append("launch")
        self.pid += 1
        self.loaded = self.ssh.installed
        self.title = "Original"
        if self.loaded and not self.wrong_title:
            project = self.app.theos.project(self.loaded["build"]["project_id"])
            self.title = project["hooks"][0]["spec"]["title"]
        return {"pid": self.pid}

    async def rpc(self, device_id, session_id, method, arguments=None):
        self.session(device_id, session_id)
        args = arguments or {}
        view = {"view_id": session_id + ":object_1", "class_name": "UIButton", "is_button": True, "text": self.title,
            "accessibility_identifier": "fixture.button", "controller": {"class_name": "DecompilerFixtureViewController", "observed": True}, "observed": True}
        if method in {"snapshot", "find_views"}:
            return {"views": [view], "truncated": False}
        if method == "inspect_view":
            return {**view, "targets": [{"target_class": "DecompilerFixtureViewController", "selector": "buttonTapped:", "control_event": 64, "observed": True}]}
        if method == "get_method_implementation":
            return {"class_name": args["class_name"], "selector": args["selector"], "type_encoding": "v20@0:8B16", "observed": True}
        if method == "dump_class":
            return {"hierarchy": ["DecompilerFixtureViewController", "UIViewController", "UIResponder", "NSObject"]}
        if method == "identity":
            return {"executable": "/Applications/DecompilerFixture.app/DecompilerFixture", "main_image": {"architecture": "arm64"}, "observed": True}
        if method == "tweak_state":
            return {"loaded": bool(self.loaded), "build_marker": self.loaded["build"]["build_marker"] if self.loaded else None, "invocation_count": 1 if self.loaded else 0, "observed": True}
        raise AssertionError("Unexpected fake RPC: " + method)

    def events(self, *args, **kwargs):
        return {"events": []}

    async def close(self):
        pass
