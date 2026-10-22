from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Any

from pydantic import Field

from flex_mcp.adapters.theos import HookSpec, ProjectSpec
from flex_mcp.app import Application
from flex_mcp.config import StrictModel
from flex_mcp.core.errors import Code, FlexError
from flex_mcp.core.registry import new_id
from flex_mcp.tools.models import Identifier
from flex_mcp.tools.tweak import Deploy, Verify, validate
from flex_mcp.workflows.deployment import DeploymentService


class DevelopRequest(StrictModel):
    workflow_id: Identifier | None = None
    device_id: Identifier | None = None
    bundle_id: Identifier | None = None
    accessibility_identifier: str | None = Field(default=None, min_length=1, max_length=255)
    replacement_title: str | None = Field(default=None, max_length=512)
    approval_id: str | None = None
    restart: bool = True
    max_repairs: int = Field(default=2, ge=0, le=3)
    background: bool = True


def repair_generated_source(path: Path, build: dict[str, Any]) -> list[str]:
    """Only deterministic repairs supported by diagnostics; never guess a method ABI."""
    source_path = path / "Tweak.xm"
    source = source_path.read_text()
    actions = []
    messages = "\n".join(item.get("message", "") for item in build.get("diagnostics", []))
    if re.search(r"unknown type name '(?:UIView|UIViewController|NSString|UIButton|BOOL)'", messages) and "#import <UIKit/UIKit.h>" not in source:
        source = "#import <UIKit/UIKit.h>\n" + source
        actions.append("Restore the UIKit header required by the reported missing types")
    if "FLEX_MCP_BUILD_ID" in messages and '#include "BuildIdentity.h"' not in source:
        source = '#include "BuildIdentity.h"\n' + source
        actions.append("Restore the build identity header required by the compiler diagnostic")
    if actions:
        source_path.write_text(source)
    return actions


class DevelopWorkflow:
    def __init__(self, app: Application):
        self.app = app

    def save(self, report: dict[str, Any], phase: str) -> dict[str, Any]:
        report["phase"] = phase
        self.app.registry.save(report["workflow_id"], "workflow", report, phase)
        return report

    async def run(self, request: DevelopRequest) -> dict[str, Any]:
        if request.workflow_id:
            report = self.app.registry.get(request.workflow_id, "workflow")
            if report["phase"] != "awaiting_approval":
                raise FlexError(Code.INVALID_INPUT, "Only a workflow awaiting deployment approval can be resumed", phase=report["phase"])
        else:
            if not request.device_id or not request.bundle_id or not request.accessibility_identifier or request.replacement_title is None:
                raise FlexError(Code.INVALID_INPUT, "A new workflow requires device_id, bundle_id, accessibility_identifier and replacement_title")
            self.app.permissions.device(request.device_id, request.bundle_id)
            report = {"workflow_id": new_id("workflow"), "target_application": {"device_id": request.device_id, "bundle_id": request.bundle_id},
                "request": request.model_dump(), "evidence": [], "inspected_classes_and_methods": [], "generated_source_files": [],
                "build_results": [], "deployment_results": None, "verification": None, "logs": None, "rollback": None, "repairs": [], "success": False}
            self.save(report, "inspecting")
            try:
                await self.prepare(report, request)
            except asyncio.CancelledError:
                self.save(report, "cancelled")
                raise
            except FlexError as exc:
                report["error"] = {"code": exc.code, "message": exc.message, "details": exc.details}
                return self.save(report, "build_failed" if exc.code == Code.BUILD_FAILED else "inspection_failed")
        target = report["target_application"]
        self.app.permissions.device(target["device_id"], target["bundle_id"])
        session_id = report["session_id"]
        try:
            self.app.frida.session(target["device_id"], session_id)
        except FlexError:
            attached = await self.app.frida.attach(target["device_id"], target["bundle_id"])
            session_id = report["session_id"] = attached["session_id"]
        deployment = DeploymentService(self.app)
        original = report["request"]
        try:
            record = await deployment.deploy(Deploy(device_id=target["device_id"], session_id=session_id, build_id=report["build_results"][-1]["build_id"], restart=original["restart"], approval_id=request.approval_id))
        except FlexError as exc:
            if exc.code in (Code.APPROVAL_REQUIRED, Code.APPROVAL_INVALID):
                if exc.code == Code.APPROVAL_REQUIRED:
                    report["approval"] = exc.details
                else:
                    report["approval_error"] = exc.message
                    # A restart/expiry changes the exact approval scope. Present a fresh
                    # concrete request rather than stranding the operator with an old ID.
                    try:
                        await deployment.deploy(Deploy(device_id=target["device_id"], session_id=session_id, build_id=report["build_results"][-1]["build_id"], restart=original["restart"]))
                    except FlexError as pending:
                        if pending.code != Code.APPROVAL_REQUIRED:
                            raise
                        report["approval"] = pending.details
                return self.save(report, "awaiting_approval")
            report["error"] = {"code": exc.code, "message": exc.message, "details": exc.details}
            report["rollback"] = exc.details.get("rollback")
            return self.save(report, "deployment_failed")
        report["deployment_results"] = record
        report["session_id"] = record["session_id"]
        self.save(report, "verifying")
        try:
            verification_request = Verify(deployment_id=record["deployment_id"], session_id=record["session_id"], accessibility_identifier=original["accessibility_identifier"], expected_title=original["replacement_title"])
            for attempt in range(12):
                evidence = await deployment.verify(verification_request)
                report["verification"] = evidence
                if evidence["verified"] or evidence["crashes"]:
                    break
                if attempt < 11:
                    await asyncio.sleep(0.5)
            report["logs"] = await deployment.logs(record["deployment_id"])
            if report["verification"]["verified"]:
                report["success"] = True
                return self.save(report, "verified")
            report["failure_diagnosis"] = {key: report["verification"].get(key) for key in ("loaded", "hook_invoked", "behavior_observed", "crashes")}
        except BaseException as exc:
            report["verification_error"] = {"type": type(exc).__name__, "message": str(exc)[:1000]}
            report["rollback"] = await asyncio.shield(deployment.rollback_after_verification(record))
            self.save(report, "cancelled" if isinstance(exc, asyncio.CancelledError) else "verification_failed")
            if isinstance(exc, asyncio.CancelledError):
                raise
            return report
        report["rollback"] = await deployment.rollback_after_verification(record)
        return self.save(report, "verification_failed")

    async def prepare(self, report: dict[str, Any], request: DevelopRequest) -> None:
        assert request.device_id and request.bundle_id and request.accessibility_identifier
        device_id = request.device_id
        device = await self.app.ssh.probe(request.device_id)
        apps = await self.app.frida.applications(request.device_id)
        target = next((item for item in apps if item["bundle_id"] == request.bundle_id), None)
        if target is None or not target["pid"]:
            raise FlexError(Code.NOT_FOUND, "Launch the selected example application before developing a tweak; device_launch requires separate approval")
        attached = await self.app.frida.attach(request.device_id, request.bundle_id, target["pid"], server_version=device.get("frida_version"))
        session_id = report["session_id"] = attached["session_id"]
        report["target_application"] = {**report["target_application"], "application": target, "device": device}
        async def rpc(method: str, args: dict[str, Any]) -> dict[str, Any]:
            return await self.app.frida.rpc(device_id, session_id, method, args)
        snapshot = await rpc("snapshot", {"depth": 8, "max_nodes": 500, "limit": 100, "include_text": False})
        found = await rpc("find_views", {"accessibility_identifier": request.accessibility_identifier, "depth": 20, "max_nodes": 1500, "limit": 100, "include_text": True})
        if len(found.get("views", [])) != 1:
            raise FlexError(Code.INVALID_INPUT, "Accessibility identifier must resolve to one observed button", matches=len(found.get("views", [])))
        button = await rpc("inspect_view", {"view_id": found["views"][0]["view_id"], "include_text": True})
        if not (button.get("is_button") or button.get("class_name") == "UIButton") or not button.get("controller"):
            raise FlexError(Code.INVALID_INPUT, "Selected view must be a UIButton with an observed controller responder")
        class_name = button["controller"]["class_name"]
        method = await rpc("get_method_implementation", {"class_name": class_name, "selector": "viewDidAppear:", "class_method": False})
        report["inspected_classes_and_methods"] = [{"class_name": class_name, "method": method, "button_actions": button.get("targets", [])}]
        report["evidence"].extend([{"source": "UIKit snapshot", "observed": True, "data": snapshot}, {"source": "UIButton target-action and responder chain", "observed": True, "data": button}, {"source": "Objective-C method metadata", "observed": True, "data": method}])
        report["baseline_title"] = button.get("text")
        environment = self.app.theos.environment()
        identity = await rpc("identity", {})
        architecture = identity.get("main_image", {}).get("architecture") or device["architecture"]
        if architecture not in {"arm64", "arm64e"}:
            raise FlexError(Code.UNAVAILABLE, "Could not determine a supported target process architecture", architecture=architecture)
        sdk_version = environment["sdks"][-1]["version"]
        device_version = tuple(map(int, device["ios_version"].split(".")))
        sdk_tuple = tuple(map(int, sdk_version.split(".")))
        deployment_target = ".".join(map(str, min(device_version, sdk_tuple)[:2]))
        suffix = report["workflow_id"].split("_")[-1][:10]
        spec = ProjectSpec(name="FLEXTitle" + suffix, package_id="dev.flex.generated." + suffix, bundle_id=request.bundle_id,
            rootless=device["mode"] == "rootless", architectures=[architecture], sdk_version=sdk_version, deployment_target=deployment_target)
        project = self.app.theos.create(spec)
        report["project_id"] = project["project_id"]
        report["generated_source_files"] = project["files"]
        hook = HookSpec(class_name=class_name, selector="viewDidAppear:", type_encoding=method["type_encoding"],
            accessibility_identifier=request.accessibility_identifier, title=request.replacement_title)
        evidence = await validate(self.app, request.device_id, session_id, hook, request.bundle_id)
        self.app.theos.write_hook(project["project_id"], hook, evidence)
        self.save(report, "building")
        for attempt in range(request.max_repairs + 1):
            build = await self.app.theos.build(project["project_id"])
            report["build_results"].append(build)
            if build["success"]:
                return
            if attempt >= request.max_repairs:
                break
            repairs = repair_generated_source(Path(project["path"]), build)
            if not repairs:
                break
            report["repairs"].extend(repairs)
        raise FlexError(Code.BUILD_FAILED, "Theos compilation failed and no further supported deterministic repair is available", build_id=report["build_results"][-1]["build_id"])


def register(app: Application) -> None:
    async def develop(request: DevelopRequest) -> dict[str, Any]:
        if request.background:
            return app.jobs.start("develop_tweak", lambda: DevelopWorkflow(app).run(request))
        return await DevelopWorkflow(app).run(request)
    app.tools.add("develop_tweak", DevelopRequest, develop, "Inspect one target button, validate a controller lifecycle ABI, generate/build a Logos title tweak, pause for exact installation approval, then deploy, observe behavior and roll back failures. Resume with workflow_id and operator-granted approval_id.", read_only=False, timeout=app.settings.build_timeout * 4 + 300)
