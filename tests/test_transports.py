from __future__ import annotations

import asyncio
import hashlib
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import asyncssh
import pytest

from flex_mcp.adapters.frida import FridaAdapter
from flex_mcp.adapters.ssh import SSHAdapter
from flex_mcp.config import DeviceConfig, Settings
from flex_mcp.core.errors import FlexError
from flex_mcp.core.registry import Registry


@asynccontextmanager
async def ssh_server(tmp_path: Path):
    host_key = asyncssh.generate_private_key("ssh-ed25519")
    client_key = asyncssh.generate_private_key("ssh-ed25519")
    key_path = tmp_path / "client_key"
    key_path.write_bytes(client_key.export_private_key())
    key_path.chmod(0o600)
    remote = tmp_path / "remote"
    remote.mkdir()

    class Server(asyncssh.SSHServer):
        def begin_auth(self, username):
            return True

        def public_key_auth_supported(self):
            return True

        def validate_public_key(self, username, key):
            return username == "tester" and key.export_public_key() == client_key.export_public_key()

    async def process(session):
        if session.command.endswith("; bounded-output"):
            session.stdout.write("a" * 300000)
        elif session.command.endswith("; wait"):
            await asyncio.sleep(2)
        else:
            session.stdout.write("architecture=arm64\nios_version=16.5\nmode=rootless\nprefix=/var/jb\ndpkg=/var/jb/usr/bin/dpkg\nfrida_version=17.24.3\n")
        session.exit(0)

    listener = await asyncssh.create_server(Server, "127.0.0.1", 0, server_host_keys=[host_key], process_factory=process,
        sftp_factory=lambda channel: asyncssh.SFTPServer(channel, chroot=str(remote)))
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text(f"[127.0.0.1]:{listener.get_port()} " + host_key.export_public_key().decode())
    settings = Settings(workspace=tmp_path, state_dir=tmp_path / ".state", operation_timeout=1,
        devices={"test": DeviceConfig(host="127.0.0.1", port=listener.get_port(), username="tester", client_keys=[key_path],
            known_hosts=known_hosts, staging_directory="/staging", download_roots=["/staging"])})
    adapter = SSHAdapter(settings)
    try:
        yield adapter, remote
    finally:
        await adapter.close()
        listener.close()
        await listener.wait_closed()


async def test_real_ssh_public_key_pool_probe_and_limits(tmp_path):
    async with ssh_server(tmp_path) as (adapter, _):
        first = await adapter.connect("test")
        assert await adapter.connect("test") is first
        probe = await adapter.probe("test")
        assert probe["architecture"] == "arm64" and probe["mode"] == "rootless"
        with pytest.raises(FlexError) as oversized:
            await adapter._run("test", "bounded-output")
        assert oversized.value.code == "LIMIT_EXCEEDED"
        with pytest.raises(FlexError) as timed_out:
            await adapter._run("test", "wait", timeout=0.05)
        assert timed_out.value.code == "TIMEOUT"
        first.close()
        await first.wait_closed()
        assert await adapter.connect("test") is not first


async def test_real_ssh_rejects_unpinned_host_key(tmp_path):
    async with ssh_server(tmp_path) as (adapter, _):
        wrong = asyncssh.generate_private_key("ssh-ed25519")
        device = adapter.settings.devices["test"]
        device.known_hosts.write_text(f"[127.0.0.1]:{device.port} " + wrong.export_public_key().decode())
        with pytest.raises(FlexError) as rejected:
            await adapter.connect("test")
        assert rejected.value.code == "SSH_ERROR"


async def test_ios_hardware_model_is_not_used_as_cpu_architecture(settings):
    adapter = SSHAdapter(settings)
    adapter._run = AsyncMock(return_value={"exit_status": 0, "stdout": "hardware_model=iPhone11,8\ncpu_type=16777228\ncpu_subtype=2\nios_version=16.0\nmode=rootless\n", "stderr": ""})
    info = await adapter.probe("test")
    assert info["hardware_model"] == "iPhone11,8"
    assert info["architecture"] == "arm64"
    assert info["cpu_subtype"] == "2"
    adapter._run.return_value["stdout"] = "hardware_model=iPhone11,8\ncpu_type=\nios_version=16.0\n"
    assert (await adapter.probe("test"))["architecture"] == "unknown"


async def test_real_sftp_atomic_transfers_and_symlink_confinement(tmp_path):
    async with ssh_server(tmp_path) as (adapter, remote):
        source = tmp_path / "source.bin"
        source.write_bytes(b"bounded artifact")
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        await adapter.upload("test", source, "/staging/artifact.bin", expected_sha256=digest)
        assert (remote / "staging/artifact.bin").read_bytes() == source.read_bytes()
        assert (remote / "staging").stat().st_mode & 0o777 == 0o700
        assert not list((remote / "staging").glob("*.uploading"))
        target = tmp_path / "download.bin"
        await adapter.download("test", "/staging/artifact.bin", target)
        assert target.read_bytes() == source.read_bytes()
        with pytest.raises(FlexError) as changed:
            await adapter.upload("test", source, "/staging/changed.bin", expected_sha256="0" * 64)
        assert changed.value.code == "IDENTITY_MISMATCH" and not (remote / "staging/changed.bin").exists()
        (remote / "outside").mkdir()
        (remote / "outside/private").write_text("do not read")
        (remote / "staging/escape").symlink_to("../outside")
        with pytest.raises(FlexError) as escaped:
            await adapter.download("test", "/staging/escape/private", tmp_path / "escaped")
        assert escaped.value.code == "NOT_ALLOWED" and not (tmp_path / "escaped").exists()
        with pytest.raises(FlexError):
            await adapter.upload("test", source, "/staging/../outside/file")


class Cancellable:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def cancel(self):
        pass


async def test_frida_adapter_uses_real_session_lifecycle_with_sdk_fake(settings):
    callbacks, messages = {}, {}
    counters = {"detach": 0, "unload": 0}

    def dispatch(method, args):
        if method == "initialize":
            return {"bundle_id": "dev.flex.fixture", "pid": 42}
        return {"observed": True, "method": method}

    script = SimpleNamespace(on=lambda event, fn: messages.update({event: fn}), load=lambda: None,
        unload=lambda: counters.update(unload=counters["unload"] + 1), exports_sync=SimpleNamespace(dispatch=dispatch))
    handle = SimpleNamespace(on=lambda event, fn: callbacks.update({event: fn}), create_script=lambda *args, **kwargs: script,
        detach=lambda: counters.update(detach=counters["detach"] + 1))
    device = SimpleNamespace(enumerate_applications=lambda **kwargs: [SimpleNamespace(identifier="dev.flex.fixture", name="Fixture", pid=42, parameters={})], attach=lambda pid: handle)
    api = SimpleNamespace(__version__="17.24.3", Cancellable=Cancellable, get_device=lambda *args, **kwargs: device)
    registry = Registry(settings.state_dir)
    adapter = FridaAdapter(settings, registry, api=api)
    try:
        session, repeated = await asyncio.gather(adapter.attach("test", "dev.flex.fixture", 42, server_version="17.24.3"), adapter.attach("test", "dev.flex.fixture", 42, server_version="17.24.3"))
        assert session["session_id"] == repeated["session_id"]
        session_id = session["session_id"]
        assert session["compatibility"]["verified"]
        assert (await adapter.rpc("test", session_id, "snapshot"))["observed"]
        messages["message"]({"type": "send", "payload": {"type": "method_enter", "password": "sensitive"}})
        await asyncio.sleep(0)
        assert adapter.events("test", session_id)["events"][0]["password"] == "[REDACTED]"
        callbacks["detached"]("process-terminated")
        await asyncio.sleep(0)
        with pytest.raises(FlexError):
            await adapter.rpc("test", session_id, "snapshot")
        await adapter.detach("test", session_id)
        assert counters == {"detach": 1, "unload": 1}
    finally:
        registry.close()


async def test_frida_major_version_and_wrong_pid_are_rejected(settings):
    registry = Registry(settings.state_dir)
    adapter = FridaAdapter(settings, registry, api=SimpleNamespace(__version__="17.24.3"))
    adapter.applications = AsyncMock(return_value=[{"bundle_id": "dev.flex.fixture", "pid": 42}])
    try:
        with pytest.raises(FlexError) as mismatch:
            await adapter.attach("test", "dev.flex.fixture", server_version="16.0.0")
        assert mismatch.value.code == "FRIDA_ERROR"
        with pytest.raises(FlexError) as wrong_pid:
            await adapter.attach("test", "dev.flex.fixture", pid=99, server_version="17.24.3")
        assert wrong_pid.value.code == "IDENTITY_MISMATCH"
    finally:
        registry.close()


async def test_frida_attach_failure_identifies_the_native_phase(settings):
    def attach(pid):
        raise RuntimeError("timeout was reached")

    device = SimpleNamespace(attach=attach)
    api = SimpleNamespace(__version__="17.24.3", Cancellable=Cancellable)
    registry = Registry(settings.state_dir)
    adapter = FridaAdapter(settings, registry, api=api)
    adapter.applications = AsyncMock(return_value=[{"bundle_id": "dev.flex.fixture", "pid": 42}])
    adapter.device = AsyncMock(return_value=device)
    try:
        with pytest.raises(FlexError) as failed:
            await adapter.attach("test", "dev.flex.fixture", server_version="17.24.3")
        assert failed.value.details["phase"] == "process_attach"
        assert failed.value.details["diagnostic"] == "timeout was reached"
        assert not adapter.sessions
    finally:
        registry.close()
