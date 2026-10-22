from __future__ import annotations

import asyncio
import contextlib
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from flex_mcp.adapters.debian import inspect_package
from flex_mcp.adapters.theos import HookSpec
from flex_mcp.app import Application
from flex_mcp.core.errors import Code, FlexError
from flex_mcp.core.permissions import sha256
from flex_mcp.core.registry import new_id
from flex_mcp.tools.tweak import validate

if TYPE_CHECKING:
    from flex_mcp.tools.tweak import Deploy, DeploymentRequest, Verify


class DeploymentService:
    def __init__(self, app: Application):
        self.app = app

    def save(self, record: dict[str, Any], phase: str) -> None:
        record["phase"] = phase
        self.app.registry.save(record["deployment_id"], "deployment", record, phase)

    def record(self, deployment_id: str) -> dict[str, Any]:
        record = self.app.registry.get(deployment_id, "deployment")
        self.app.permissions.device(record["device_id"], record["bundle_id"])
        return record

    async def _build(self, build_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
        build = self.app.registry.get(build_id, "build")
        if not build["success"] or not build.get("package_path"):
            raise FlexError(Code.BUILD_FAILED, "Deployment requires a successful packaged build")
        path = self.app.permissions.local_path(Path(build["package_path"]), must_exist=True)
        if sha256(path) != build["package_sha256"]:
            raise FlexError(Code.IDENTITY_MISMATCH, "Package contents changed after the build")
        metadata = await asyncio.to_thread(inspect_package, path, build["spec"], self.app.settings.max_transfer_bytes)
        return build, metadata

    async def deploy(self, request: Deploy) -> dict[str, Any]:
        async with self.app.deployment_locks.setdefault(request.device_id, asyncio.Lock()):
            build, metadata = await self._build(request.build_id)
            spec = build["spec"]
            self.app.permissions.device(request.device_id, spec["bundle_id"])
            project = self.app.theos.project(build["project_id"])
            if self.app.theos.fingerprint(build["project_id"]) != build["source_hash"]:
                raise FlexError(Code.IDENTITY_MISMATCH, "Sources changed after build; rebuild before deployment")
            session = self.app.frida.session(request.device_id, request.session_id)
            if session.bundle_id != spec["bundle_id"]:
                raise FlexError(Code.IDENTITY_MISMATCH, "Deployment session targets another application")
            for entry in project["hooks"]:
                await validate(self.app, request.device_id, request.session_id, HookSpec.model_validate(entry["spec"]), spec["bundle_id"])
            device = await self.app.ssh.probe(request.device_id)
            if (device["mode"] == "rootless") != spec["rootless"]:
                raise FlexError(Code.IDENTITY_MISMATCH, "Package scheme differs from the observed jailbreak environment")
            before = await self.app.ssh.package_status(request.device_id, spec["package_id"])
            previous: dict[str, Any] | None = None
            if before["installed"]:
                candidates = [item for item in self.app.registry.list("deployment") if item["device_id"] == request.device_id and item["package_id"] == spec["package_id"] and item["phase"] in {"installed", "verified", "verification_failed"}]
                if not candidates:
                    raise FlexError(Code.NOT_ALLOWED, "Cannot replace an unmanaged installed package without a recoverable backup")
                prior, prior_metadata = await self._build(candidates[0]["build_id"])
                actual = await self.app.ssh.file_sha256(request.device_id, prior_metadata["dylib_path"])
                if actual != prior_metadata["dylib_sha256"] or before["version"] != prior_metadata["version"]:
                    raise FlexError(Code.IDENTITY_MISMATCH, "Installed package differs from the managed rollback artifact")
                previous = {"deployment_id": candidates[0]["deployment_id"], "build_id": candidates[0]["build_id"], "package_sha256": prior["package_sha256"], "metadata": prior_metadata}
            scope = {"device_id": request.device_id, "bundle_id": spec["bundle_id"], "session_id": request.session_id,
                "package_id": spec["package_id"], "package_sha256": build["package_sha256"], "restart": request.restart,
                "previous_package_sha256": previous["package_sha256"] if previous else None, "rollback_on_failure": True}
            self.app.permissions.require("tweak_deploy", scope, request.approval_id)
            deployment_id = new_id("deployment")
            record = {"deployment_id": deployment_id, "device_id": request.device_id, "bundle_id": spec["bundle_id"], "package_id": spec["package_id"],
                "build_id": request.build_id, "metadata": metadata, "previous": previous, "started_at": time.time(), "restart": request.restart,
                "session_id": request.session_id, "executable": session.bundle_id.rsplit(".", 1)[-1], "logs": [], "rollback": None}
            identity = await self.app.frida.rpc(request.device_id, request.session_id, "identity", {})
            record["executable"] = Path(identity.get("executable", record["executable"])).name
            self.save(record, "staging")

            async def apply() -> None:
                remote = self.app.settings.devices[request.device_id].staging_directory + "/" + deployment_id + ".deb"
                await self.app.ssh.upload(request.device_id, Path(build["package_path"]), remote)
                # Verify transfer bytes before privileged package installation.
                if await self.app.ssh.file_sha256(request.device_id, remote) != build["package_sha256"]:
                    raise FlexError(Code.IDENTITY_MISMATCH, "Uploaded package checksum does not match approved artifact")
                self.save(record, "installing")
                result = await self.app.ssh.install(request.device_id, remote)
                record["logs"].append(result)
                if result["exit_status"] != 0:
                    raise FlexError(Code.DEPLOY_FAILED, "dpkg did not install the package successfully")
                status = await self.app.ssh.package_status(request.device_id, spec["package_id"])
                if not status["installed"] or status["version"] != metadata["version"]:
                    raise FlexError(Code.DEPLOY_FAILED, "Package database does not confirm the installed version")
                actual = await self.app.ssh.file_sha256(request.device_id, metadata["dylib_path"])
                if actual != metadata["dylib_sha256"]:
                    raise FlexError(Code.IDENTITY_MISMATCH, "Installed dylib checksum differs from the built artifact")
                if request.restart:
                    await self._restart(record)
                self.save(record, "installed")
                if previous:
                    prior_record = self.record(previous["deployment_id"])
                    self.save(prior_record, "superseded")

            mutation = asyncio.create_task(apply())
            try:
                await asyncio.shield(mutation)
            except BaseException as exc:
                # Let a privileged install settle before issuing a conflicting rollback.
                if not mutation.done():
                    with contextlib.suppress(Exception, asyncio.CancelledError):
                        await asyncio.shield(mutation)
                record["failure"] = {"type": type(exc).__name__, "message": str(exc)[:1000]}
                record["rollback"] = await self.rollback_internal(record)
                self.save(record, "failed")
                if isinstance(exc, asyncio.CancelledError):
                    raise
                raise FlexError(Code.DEPLOY_FAILED, "Deployment failed; inspect rollback status", deployment_id=deployment_id, rollback=record["rollback"]) from exc
            return {**record, "verified": False, "note": "Installation is complete; runtime loading and requested behavior still require verification"}

    async def _restart(self, record: dict[str, Any]) -> None:
        device_id, bundle_id = record["device_id"], record["bundle_id"]
        for session in list(self.app.frida.sessions.values()):
            if session.active and session.device_id == device_id and session.bundle_id == bundle_id:
                await self.app.frida.detach(device_id, session.id)
        await self.app.frida.terminate(device_id, bundle_id)
        await self.app.frida.spawn(device_id, bundle_id)
        for attempt in range(5):
            try:
                attached = await self.app.frida.attach(device_id, bundle_id)
                record["session_id"] = attached["session_id"]
                return
            except FlexError as exc:
                if exc.code != Code.NOT_FOUND or attempt == 4:
                    raise
                await asyncio.sleep(0.5)

    async def verify(self, request: Verify) -> dict[str, Any]:
        device_id = self.record(request.deployment_id)["device_id"]
        async with self.app.deployment_locks.setdefault(device_id, asyncio.Lock()):
            return await self._verify(request)

    async def _verify(self, request: Verify) -> dict[str, Any]:
        record = self.record(request.deployment_id)
        if record["phase"] not in {"installed", "verified", "verification_failed"}:
            raise FlexError(Code.INVALID_INPUT, "Only a currently installed deployment can be verified", phase=record["phase"])
        await self._assert_current(record)
        session = self.app.frida.session(record["device_id"], request.session_id)
        if session.bundle_id != record["bundle_id"]:
            raise FlexError(Code.IDENTITY_MISMATCH, "Verification session belongs to another application")
        build = self.app.registry.get(record["build_id"], "build")
        marker = await self.app.frida.rpc(record["device_id"], request.session_id, "tweak_state", {"module_name": build["spec"]["name"] + ".dylib"})
        views = await self.app.frida.rpc(record["device_id"], request.session_id, "find_views", {"accessibility_identifier": request.accessibility_identifier, "include_text": True, "depth": 20, "max_nodes": 1500, "limit": 100})
        matches = views.get("views", [])
        behavior = len(matches) == 1 and (matches[0].get("is_button") or matches[0].get("class_name") == "UIButton") and matches[0].get("text") == request.expected_title
        loaded = marker.get("loaded") is True and marker.get("build_marker") == build["build_marker"]
        invoked = marker.get("invocation_count", 0) > 0
        crashes = await self.app.ssh.list_crashes(record["device_id"], record["executable"], record["started_at"])
        verified = loaded and invoked and behavior and not crashes
        evidence = {"loaded": loaded, "hook_invoked": invoked, "behavior_observed": behavior, "marker": marker, "views": matches, "crashes": crashes,
            "session_id": request.session_id, "observed": True, "verified": verified}
        record["verification"] = evidence
        self.save(record, "verified" if verified else "verification_failed")
        return evidence

    async def logs(self, deployment_id: str) -> dict[str, Any]:
        record = self.record(deployment_id)
        crashes = await self.app.ssh.list_crashes(record["device_id"], record["executable"], record["started_at"])
        events: dict[str, Any] = {"events": [], "active": False}
        if record.get("session_id") in self.app.frida.sessions:
            events = self.app.frida.events(record["device_id"], record["session_id"], limit=100)
        return {"deployment_id": deployment_id, "package_logs": record["logs"], "crashes": crashes, "trace": events, "note": "Only managed operation logs and app crash filenames are collected; unified log contents are not harvested"}

    async def rollback_internal(self, record: dict[str, Any]) -> dict[str, Any]:
        try:
            if record.get("previous"):
                previous, metadata = await self._build(record["previous"]["build_id"])
                remote = self.app.settings.devices[record["device_id"]].staging_directory + "/rollback-" + record["deployment_id"] + ".deb"
                await self.app.ssh.upload(record["device_id"], Path(previous["package_path"]), remote)
                if await self.app.ssh.file_sha256(record["device_id"], remote) != previous["package_sha256"]:
                    raise FlexError(Code.IDENTITY_MISMATCH, "Rollback upload checksum differs")
                result = await self.app.ssh.install(record["device_id"], remote)
                restored = result["exit_status"] == 0 and await self.app.ssh.file_sha256(record["device_id"], metadata["dylib_path"]) == metadata["dylib_sha256"]
                action = "previous_package_restored"
            else:
                result = await self.app.ssh.uninstall(record["device_id"], record["package_id"])
                restored = result["exit_status"] == 0 and not (await self.app.ssh.package_status(record["device_id"], record["package_id"]))["installed"]
                action = "new_package_removed"
            record["logs"].append(result)
            if record.get("restart"):
                await self._restart(record)
            if restored and (record.get("previous") or {}).get("deployment_id"):
                previous_record = self.record(record["previous"]["deployment_id"])
                previous_record["session_id"] = record["session_id"]
                previous_record.pop("verification", None)
                self.save(previous_record, "installed")
            return {"restored": restored, "action": action, "runtime_restoration_verified": False}
        except Exception as exc:
            return {"restored": False, "error": type(exc).__name__, "message": str(exc)[:1000], "operator_action_required": True}

    async def _assert_current(self, record: dict[str, Any]) -> None:
        if record["phase"] not in {"installed", "verified", "verification_failed", "rollback_failed", "uninstall_failed", "interrupted"}:
            raise FlexError(Code.INVALID_INPUT, "Deployment is no longer the current installed package", phase=record["phase"])
        status = await self.app.ssh.package_status(record["device_id"], record["package_id"])
        if not status["installed"] or status["version"] != record["metadata"]["version"] or await self.app.ssh.file_sha256(record["device_id"], record["metadata"]["dylib_path"]) != record["metadata"]["dylib_sha256"]:
            raise FlexError(Code.IDENTITY_MISMATCH, "Installed package changed; refusing to mutate it using a stale deployment record")

    async def rollback_after_verification(self, record: dict[str, Any]) -> dict[str, Any]:
        async with self.app.deployment_locks.setdefault(record["device_id"], asyncio.Lock()):
            current = self.record(record["deployment_id"])
            try:
                # Another approved operation may have run between verification
                # polls. The old rollback grant cannot authorize removing its result.
                await self._assert_current(current)
            except FlexError as exc:
                return {"restored": False, "operator_action_required": True, "error": exc.code,
                    "message": "Package state changed or is uncertain; no automatic rollback was performed"}
            result = await self.rollback_internal(current)
            current["rollback"] = result
            self.save(current, "rolled_back" if result["restored"] else "rollback_failed")
            return result

    @staticmethod
    async def _settle(work: Any) -> dict[str, Any]:
        task = asyncio.create_task(work)
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            with contextlib.suppress(Exception, asyncio.CancelledError):
                await asyncio.shield(task)
            raise

    async def rollback(self, request: DeploymentRequest) -> dict[str, Any]:
        device_id = self.record(request.deployment_id)["device_id"]
        async with self.app.deployment_locks.setdefault(device_id, asyncio.Lock()):
            record = self.record(request.deployment_id)
            await self._assert_current(record)
            scope = {"deployment_id": request.deployment_id, "device_id": record["device_id"], "bundle_id": record["bundle_id"], "restart": request.restart, "previous": record.get("previous"), "installed_dylib_sha256": record["metadata"]["dylib_sha256"]}
            self.app.permissions.require("tweak_rollback", scope, request.approval_id)
            record["restart"] = request.restart
            async def apply() -> dict[str, Any]:
                result = await self.rollback_internal(record)
                record["rollback"] = result
                self.save(record, "rolled_back" if result["restored"] else "rollback_failed")
                return {"deployment_id": request.deployment_id, "session_id": record.get("session_id"), **result}
            return await self._settle(apply())

    async def uninstall(self, request: DeploymentRequest) -> dict[str, Any]:
        device_id = self.record(request.deployment_id)["device_id"]
        async with self.app.deployment_locks.setdefault(device_id, asyncio.Lock()):
            record = self.record(request.deployment_id)
            await self._assert_current(record)
            self.app.permissions.require("tweak_uninstall", {"deployment_id": request.deployment_id, "device_id": record["device_id"], "bundle_id": record["bundle_id"], "package_id": record["package_id"], "restart": request.restart, "installed_dylib_sha256": record["metadata"]["dylib_sha256"]}, request.approval_id)
            async def apply() -> dict[str, Any]:
                result = await self.app.ssh.uninstall(record["device_id"], record["package_id"])
                removed = result["exit_status"] == 0 and not (await self.app.ssh.package_status(record["device_id"], record["package_id"]))["installed"]
                record["logs"].append(result)
                self.save(record, "uninstalled" if removed else "uninstall_failed")
                if request.restart and removed:
                    await self._restart(record)
                    self.save(record, "uninstalled")
                return {"deployment_id": request.deployment_id, "removed": removed, "session_id": record["session_id"], "behavior_restoration_verified": False}
            return await self._settle(apply())
