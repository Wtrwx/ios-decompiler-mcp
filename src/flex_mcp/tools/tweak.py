from __future__ import annotations

from typing import Any

from pydantic import Field

from flex_mcp.adapters.theos import HookSpec, ProjectSpec
from flex_mcp.app import Application
from flex_mcp.config import StrictModel
from flex_mcp.core.errors import Code, FlexError
from flex_mcp.tools.models import Empty, Identifier, MethodRequest


class CreateProject(StrictModel):
    spec: ProjectSpec
    device_id: Identifier | None = None


class ProjectRequest(StrictModel):
    project_id: Identifier


class GenerateHook(ProjectRequest):
    hook: HookSpec
    device_id: Identifier | None = None
    session_id: Identifier | None = None


class ValidateHook(MethodRequest):
    project_id: Identifier


class Build(ProjectRequest):
    background: bool = True


class BuildErrors(StrictModel):
    build_id: Identifier


class Deploy(StrictModel):
    device_id: Identifier
    session_id: Identifier
    build_id: Identifier
    restart: bool = False
    approval_id: str | None = None


class Verify(StrictModel):
    deployment_id: Identifier
    session_id: Identifier
    accessibility_identifier: str = Field(min_length=1, max_length=255)
    expected_title: str = Field(max_length=512)


class DeploymentRequest(StrictModel):
    deployment_id: Identifier
    approval_id: str | None = None
    restart: bool = False


async def validate(app: Application, device_id: str, session_id: str, hook: HookSpec, bundle_id: str) -> dict[str, Any]:
    session = app.frida.session(device_id, session_id)
    if session.bundle_id != bundle_id:
        raise FlexError(Code.IDENTITY_MISMATCH, "Hook validation session is for another application")
    evidence = await app.frida.rpc(device_id, session_id, "get_method_implementation", {"class_name": hook.class_name, "selector": hook.selector, "class_method": hook.class_method})
    if evidence.get("type_encoding") != hook.type_encoding:
        raise FlexError(Code.IDENTITY_MISMATCH, "Observed method ABI differs from proposed Logos signature", proposed=hook.type_encoding, observed=evidence.get("type_encoding"))
    if hook.behavior == "set_button_title":
        klass = await app.frida.rpc(device_id, session_id, "dump_class", {"class_name": hook.class_name, "limit": 1})
        if "UIViewController" not in klass.get("hierarchy", []):
            raise FlexError(Code.INVALID_INPUT, "Button-title recipe requires an observed UIViewController subclass")
    return {"device_id": device_id, "session_id": session_id, "bundle_id": bundle_id, "method": evidence, "observed": True}


def register(app: Application) -> None:
    async def environment(_: Empty) -> dict[str, Any]:
        return app.theos.environment()

    async def create(request: CreateProject) -> dict[str, Any]:
        if request.device_id:
            app.permissions.device(request.device_id, request.spec.bundle_id)
            info = await app.ssh.probe(request.device_id)
            if request.spec.rootless != (info["mode"] == "rootless"):
                raise FlexError(Code.IDENTITY_MISMATCH, "Project packaging scheme differs from observed device environment")
            if tuple(map(int, request.spec.deployment_target.split("."))) > tuple(map(int, info["ios_version"].split("."))):
                raise FlexError(Code.INVALID_INPUT, "Project deployment target exceeds the device's iOS version")
        return app.theos.create(request.spec)

    async def generate(request: GenerateHook) -> dict[str, Any]:
        project = app.theos.project(request.project_id)
        evidence = None
        if request.device_id and request.session_id:
            app.permissions.device(request.device_id, project["spec"]["bundle_id"])
            evidence = await validate(app, request.device_id, request.session_id, request.hook, project["spec"]["bundle_id"])
        elif request.device_id or request.session_id:
            raise FlexError(Code.INVALID_INPUT, "Specify device_id and session_id together")
        return app.theos.write_hook(request.project_id, request.hook, evidence)

    async def validate_hook(request: ValidateHook) -> dict[str, Any]:
        project = app.theos.project(request.project_id)
        entry = next((entry for entry in project["hooks"] if entry["spec"]["class_name"] == request.class_name and entry["spec"]["selector"] == request.selector and entry["spec"]["class_method"] == request.class_method), None)
        if entry is None:
            raise FlexError(Code.NOT_FOUND, "Project does not contain this hook")
        hook = HookSpec.model_validate(entry["spec"])
        evidence = await validate(app, request.device_id, request.session_id, hook, project["spec"]["bundle_id"])
        return {"validated": True, "evidence": evidence}

    async def build(request: Build) -> dict[str, Any]:
        app.theos.project(request.project_id)
        if request.background:
            return app.jobs.start("tweak_build", lambda: app.theos.build(request.project_id))
        return await app.theos.build(request.project_id)

    async def errors(request: BuildErrors) -> dict[str, Any]:
        build = app.registry.get(request.build_id, "build")
        return {"build_id": request.build_id, "success": build["success"], "diagnostics": build["diagnostics"], "log": build["log"]}

    async def deploy(request: Deploy) -> dict[str, Any]:
        from flex_mcp.workflows.deployment import DeploymentService
        return await DeploymentService(app).deploy(request)

    async def verify(request: Verify) -> dict[str, Any]:
        from flex_mcp.workflows.deployment import DeploymentService
        return await DeploymentService(app).verify(request)

    async def uninstall(request: DeploymentRequest) -> dict[str, Any]:
        from flex_mcp.workflows.deployment import DeploymentService
        return await DeploymentService(app).uninstall(request)

    async def rollback(request: DeploymentRequest) -> dict[str, Any]:
        from flex_mcp.workflows.deployment import DeploymentService
        return await DeploymentService(app).rollback(request)

    async def logs(request: DeploymentRequest) -> dict[str, Any]:
        from flex_mcp.workflows.deployment import DeploymentService
        return await DeploymentService(app).logs(request.deployment_id)

    app.tools.add("tweak_environment", Empty, environment, "Discover installed Theos, make and iOS SDK versions; never install a toolchain.")
    app.tools.add("tweak_create_project", CreateProject, create, "Generate an editable app-scoped Theos/Logos project with explicit SDK, architecture and deployment target.", read_only=False)
    app.tools.add("tweak_generate_hook", GenerateHook, generate, "Add or replace a Logos hook using a known ABI and structured recipe; optionally validate against the selected process.", read_only=False)
    app.tools.add("tweak_validate_hook", ValidateHook, validate_hook, "Compare a proposed hook's encoding to observed live metadata and validate recipe requirements.")
    app.tools.add("tweak_build", Build, build, "Clean, compile and package using installed Theos; returns a cancellable background job by default.", read_only=False, timeout=app.settings.build_timeout + 10)
    app.tools.add("tweak_get_build_errors", BuildErrors, errors, "Retrieve parsed clang/Theos diagnostics and bounded build output.")
    app.tools.add("tweak_deploy", Deploy, deploy, "Validate signatures and package identity, request exact operator approval, then stage/install with rollback on failure.", read_only=False, timeout=app.settings.build_timeout + 120)
    app.tools.add("tweak_verify", Verify, verify, "Verify the exact compiled marker is loaded and the requested UI behavior is observed; compilation is insufficient.")
    app.tools.add("tweak_get_logs", DeploymentRequest, logs, "Collect app-scoped crash metadata, package operation logs and available trace events.")
    app.tools.add("tweak_uninstall", DeploymentRequest, uninstall, "Remove this managed package with explicit approval; optionally restart the selected app.", read_only=False)
    app.tools.add("tweak_rollback", DeploymentRequest, rollback, "Restore the previous managed package or remove a newly installed package; requires explicit approval outside a deployment transaction.", read_only=False)
