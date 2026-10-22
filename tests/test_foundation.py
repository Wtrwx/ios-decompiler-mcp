from __future__ import annotations

import asyncio
import time
from pathlib import Path

import pytest

from vesper.app import Application
from vesper.config import DeviceConfig, Settings
from vesper.core.errors import Code, MCPError
from vesper.core.evidence import redact
from vesper.core.permissions import canonical_scope
from vesper.core.registry import Registry


def test_configuration_environment_and_explicit_path_precedence(tmp_path: Path, monkeypatch):
    environment_config = tmp_path / "environment.toml"
    environment_config.write_text(f'workspace = "{tmp_path}"\nevent_limit = 50\n')
    explicit_config = tmp_path / "explicit.toml"
    explicit_config.write_text(f'workspace = "{tmp_path}"\nevent_limit = 100\n')
    monkeypatch.setenv("VESPER_CONFIG", str(environment_config))
    settings = Settings.load()
    assert settings.event_limit == 50
    assert settings.state_dir == tmp_path / ".vesper"
    assert Settings.load(explicit_config).event_limit == 100


def test_approval_is_bound_single_use_and_cannot_be_granted_via_mcp(app: Application):
    scope = {"device_id": "test", "sha256": "abc"}
    request = app.permissions.request("install", scope)
    assert "approve" not in app.tools.tools
    with pytest.raises(MCPError, match="Approval"):
        app.permissions.require("install", scope, request["approval_id"])
    app.registry.db.execute("UPDATE approvals SET status='granted' WHERE id=?", (request["approval_id"],))
    app.registry.db.commit()
    with pytest.raises(MCPError):
        app.permissions.require("install", {**scope, "sha256": "changed"}, request["approval_id"])
    app.permissions.require("install", scope, request["approval_id"])
    with pytest.raises(MCPError):
        app.permissions.require("install", scope, request["approval_id"])
    assert canonical_scope({"a": 1, "b": 2}) == canonical_scope({"b": 2, "a": 1})


def test_expired_approval_and_deny_by_default(app: Application):
    with pytest.raises(MCPError):
        app.permissions.device("other")
    with pytest.raises(MCPError):
        app.permissions.device("test", "com.unrelated.app")
    request = app.permissions.request("install", {})
    app.registry.db.execute("UPDATE approvals SET status='granted',expires=?", (time.time() - 1,))
    app.registry.db.commit()
    with pytest.raises(MCPError):
        app.permissions.require("install", {}, request["approval_id"])


def test_redaction():
    result = redact({"Authorization": "Bearer token", "nested": [{"password": "pw"}], "text": "Bearer abc.def password=secret", "key": "-----BEGIN PRIVATE KEY-----\nxyz\n-----END PRIVATE KEY-----"})
    assert result["Authorization"] == "[REDACTED]"
    assert "abc.def" not in result["text"] and "secret" not in result["text"]
    assert "xyz" not in result["key"]


def test_path_and_host_key_validation(app: Application, tmp_path: Path):
    outside = tmp_path.parent / "outside"
    link = tmp_path / "escape"
    link.symlink_to(outside)
    with pytest.raises(MCPError):
        app.permissions.local_path(link / "secret")
    with pytest.raises(ValueError):
        DeviceConfig(host="test", known_hosts=None)
    for path in ["/etc/passwd", "/tmp/vesper/../etc/passwd", "relative"]:
        with pytest.raises(MCPError):
            app.ssh._remote_within(path, ["/tmp/vesper"])


@pytest.mark.asyncio
async def test_tools_validate_and_return_structured_errors(app: Application):
    result = await app.tools.invoke("server_status", {})
    assert result.ok and result.data["inspection_default"] == "read_only"
    result = await app.tools.invoke("device_connect", {"device_id": "unconfigured"})
    assert not result.ok and result.error.code == Code.NOT_ALLOWED
    result = await app.tools.invoke("frida_attach", {"device_id": "test", "bundle_id": "dev.iosdecompiler.fixture", "pid": -1})
    assert result.error.code == Code.INVALID_INPUT
    result = await app.tools.invoke("does_not_exist", {})
    assert result.error.code == Code.NOT_FOUND


@pytest.mark.asyncio
async def test_job_cancellation_durable_state(app: Application):
    async def wait():
        await asyncio.Event().wait()
        return {}
    job = app.jobs.start("test", wait)
    await asyncio.sleep(0)
    result = await app.jobs.cancel(job["job_id"])
    assert result["status"] == "cancelled"


def test_live_handles_invalidated_but_projects_survive_restart(app: Application):
    app.registry.save("s", "process_session", {"pid": 1})
    app.registry.save("p", "project", {"path": "example"})
    second = Registry(app.settings.state_dir)
    second.invalidate_live_sessions()
    assert second.get("s")["status"] == "invalidated"
    assert second.get("p")["status"] == "active"
    second.close()


def test_one_server_per_state_and_approval_registry_can_coexist(app: Application):
    with pytest.raises(MCPError) as duplicate:
        Application(app.settings)
    assert duplicate.value.code == Code.UNAVAILABLE
    operator = Registry(app.settings.state_dir)
    assert operator.path == app.registry.path
    operator.close()


def test_host_restart_marks_uncertain_deployments_for_operator_recovery(app: Application):
    app.registry.save("d", "deployment", {"deployment_id": "d", "phase": "installing"}, "installing")
    app.registry.save("w", "workflow", {"phase": "verifying"}, "verifying")
    app.registry.invalidate_live_sessions()
    assert app.registry.get("d")["phase"] == "interrupted"
    assert app.registry.get("d")["interrupted_phase"] == "installing"
    assert app.registry.get("w")["status"] == "interrupted"
