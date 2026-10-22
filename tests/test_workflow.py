from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from ios_decompiler_mcp.app import Application
from ios_decompiler_mcp.core.permissions import sha256
from ios_decompiler_mcp.core.registry import new_id
from ios_decompiler_mcp.tools.tweak import DeploymentRequest
from ios_decompiler_mcp.workflows.deployment import DeploymentService
from ios_decompiler_mcp.workflows.develop_tweak import DevelopRequest, DevelopWorkflow
from tests.fakes import FakeFrida, FakeSSH
from tests.test_theos import make_deb


def grant(app: Application, approval_id: str):
    app.registry.db.execute("UPDATE approvals SET status='granted' WHERE id=? AND status='pending'", (approval_id,))
    app.registry.db.commit()


@pytest.fixture
def infrastructure(app: Application, project, monkeypatch):
    ssh = FakeSSH(app)
    frida = FakeFrida(app, ssh)
    monkeypatch.setattr(app, "ssh", ssh)
    monkeypatch.setattr(app, "frida", frida)

    async def build(project_id):
        record = app.theos.project(project_id)
        build_id = new_id("build")
        directory = Path(record["path"]) / "builds" / build_id
        directory.mkdir(parents=True)
        path = make_deb(directory, record["spec"])
        result = {"build_id": build_id, "project_id": project_id, "source_hash": app.theos.fingerprint(project_id), "success": True,
            "exit_status": 0, "package_path": str(path), "package_sha256": sha256(path), "build_marker": build_id, "spec": record["spec"], "diagnostics": [], "log": "TEST FAKE COMPILER"}
        app.registry.save(build_id, "build", result, "succeeded")
        return result
    monkeypatch.setattr(app.theos, "build", build)
    return ssh, frida


async def prepare(app):
    return await DevelopWorkflow(app).run(DevelopRequest(device_id="test", bundle_id="dev.iosdecompiler.fixture", accessibility_identifier="fixture.button", replacement_title="Tweaked", background=False))


@pytest.mark.asyncio
async def test_end_to_end_mocked_device_requires_observed_behavior_and_restores(app: Application, infrastructure):
    ssh, frida = infrastructure
    report = await prepare(app)
    assert report["phase"] == "awaiting_approval" and not report["success"]
    assert report["build_results"][-1]["success"] and not ssh.mutations
    assert report["inspected_classes_and_methods"][0]["button_actions"][0]["selector"] == "buttonTapped:"
    approval = report["approval"]["approval_id"]
    grant(app, approval)
    report = await DevelopWorkflow(app).run(DevelopRequest(workflow_id=report["workflow_id"], approval_id=approval, background=False))
    assert report["success"] and report["verification"]["verified"]
    assert report["verification"]["hook_invoked"] and frida.title == "Tweaked"
    deployment_id = report["deployment_results"]["deployment_id"]
    result = await app.tools.invoke("tweak_uninstall", {"deployment_id": deployment_id, "restart": True})
    assert not result.ok and result.error.code == "APPROVAL_REQUIRED"
    grant(app, result.error.details["approval_id"])
    restored = await DeploymentService(app).uninstall(DeploymentRequest(deployment_id=deployment_id, restart=True, approval_id=result.error.details["approval_id"]))
    assert restored["removed"] and frida.title == "Original" and ssh.installed is None


@pytest.mark.asyncio
async def test_failed_install_is_rolled_back(app: Application, infrastructure):
    ssh, _ = infrastructure
    report = await prepare(app)
    approval = report["approval"]["approval_id"]
    grant(app, approval)
    ssh.fail_install = True
    report = await DevelopWorkflow(app).run(DevelopRequest(workflow_id=report["workflow_id"], approval_id=approval, background=False))
    assert not report["success"] and report["phase"] == "deployment_failed"
    assert report["rollback"]["restored"] and "uninstall" in ssh.mutations


@pytest.mark.asyncio
async def test_successful_install_without_behavior_is_not_success(app: Application, infrastructure, monkeypatch):
    ssh, frida = infrastructure
    report = await prepare(app)
    approval = report["approval"]["approval_id"]
    grant(app, approval)
    frida.wrong_title = True
    monkeypatch.setattr("ios_decompiler_mcp.workflows.develop_tweak.asyncio.sleep", AsyncMock())
    report = await DevelopWorkflow(app).run(DevelopRequest(workflow_id=report["workflow_id"], approval_id=approval, background=False))
    assert report["phase"] == "verification_failed" and not report["success"]
    assert report["verification"]["loaded"] and not report["verification"]["behavior_observed"]
    assert report["rollback"]["restored"] and ssh.installed is None


@pytest.mark.asyncio
async def test_cancelled_install_settles_then_rolls_back(app: Application, infrastructure, monkeypatch):
    ssh, _ = infrastructure
    report = await prepare(app)
    approval = report["approval"]["approval_id"]
    grant(app, approval)
    started, release = asyncio.Event(), asyncio.Event()
    actual_install = ssh.install
    async def blocked_install(*args):
        started.set()
        await release.wait()
        return await actual_install(*args)
    monkeypatch.setattr(ssh, "install", blocked_install)
    task = asyncio.create_task(DevelopWorkflow(app).run(DevelopRequest(workflow_id=report["workflow_id"], approval_id=approval, background=False)))
    await asyncio.wait_for(started.wait(), 2)
    task.cancel()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert ssh.installed is None and "uninstall" in ssh.mutations


async def test_expired_workflow_approval_is_refreshed_without_mutations(app: Application, infrastructure):
    ssh, _ = infrastructure
    report = await prepare(app)
    old = report["approval"]["approval_id"]
    app.registry.db.execute("UPDATE approvals SET expires=0 WHERE id=?", (old,))
    app.registry.db.commit()
    report = await DevelopWorkflow(app).run(DevelopRequest(workflow_id=report["workflow_id"], approval_id=old, background=False))
    assert report["phase"] == "awaiting_approval" and report["approval"]["approval_id"] != old
    assert not ssh.mutations


async def test_stale_package_record_cannot_uninstall_changed_artifact(app: Application, infrastructure, monkeypatch):
    ssh, _ = infrastructure
    report = await prepare(app)
    approval = report["approval"]["approval_id"]
    grant(app, approval)
    report = await DevelopWorkflow(app).run(DevelopRequest(workflow_id=report["workflow_id"], approval_id=approval, background=False))
    deployment_id = report["deployment_results"]["deployment_id"]
    monkeypatch.setattr(ssh, "file_sha256", AsyncMock(return_value="a different installed artifact"))
    before = list(ssh.mutations)
    rejected = await app.tools.invoke("tweak_uninstall", {"deployment_id": deployment_id})
    assert not rejected.ok and rejected.error.code == "IDENTITY_MISMATCH"
    assert ssh.mutations == before


async def test_late_automatic_recovery_cannot_remove_a_superseding_deployment(app: Application, infrastructure):
    ssh, _ = infrastructure
    report = await prepare(app)
    approval = report["approval"]["approval_id"]
    grant(app, approval)
    report = await DevelopWorkflow(app).run(DevelopRequest(workflow_id=report["workflow_id"], approval_id=approval, background=False))
    service = DeploymentService(app)
    stale = report["deployment_results"]
    current = service.record(stale["deployment_id"])
    service.save(current, "superseded")
    before = list(ssh.mutations)
    result = await service.rollback_after_verification(stale)
    assert not result["restored"] and result["operator_action_required"]
    assert ssh.mutations == before
