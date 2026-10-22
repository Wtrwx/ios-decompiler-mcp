from __future__ import annotations

import asyncio
import json
import struct
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from tests.test_capture import BUNDLE
from tests.test_capture import capture_app as capture_app
from vesper.adapters.debug_setup import validate_debugserver
from vesper.assets.lldb_worker import inspect
from vesper.core.errors import MCPError


def ios_executable(platform=2):
    return struct.pack('<8I', 0xFEEDFACF, 0x100000C, 0, 2, 1, 24, 0, 0) + struct.pack('<6I', 0x32, 24, platform, 0, 0, 0)


@pytest.mark.parametrize('platform,valid', [(2, True), (1, False), (7, False)])
def test_debugserver_rejects_host_and_simulator_binaries(tmp_path, platform, valid):
    executable = tmp_path / 'debugserver'
    executable.write_bytes(ios_executable(platform))
    if valid:
        assert len(validate_debugserver(executable)) == 64
    else:
        with pytest.raises(MCPError):
            validate_debugserver(executable)


async def test_log_stream_reuses_session_and_pins_until_stop(capture_app):
    app, sdk = capture_app
    dispatch = sdk.dispatch

    def logs(pid, method, args):
        if method == 'app_logs':
            sdk.calls.append((method, args))
            return {'active': args['action'] != 'stop', 'entries': [], 'next_cursor': 5}
        if method == 'list_hooks':
            return {'hooks': []}
        return dispatch(pid, method, args)

    sdk.dispatch = logs
    request = {'device_id': 'test', 'bundle_id': BUNDLE}
    stopped = await app.tools.invoke('app_logs', {**request, 'action': 'stop'})
    assert stopped.ok and sdk.attaches == 0
    first = await app.tools.invoke('app_logs', {**request, 'action': 'start'})
    second = await app.tools.invoke('app_logs', {**request, 'after': 5, 'limit': 1})
    assert first.ok and second.ok and sdk.attaches == 1
    session = app.frida.session('test', first.data['session_id'])
    await app.frida.rpc('test', session.id, 'list_hooks')
    app.settings.session_idle_timeout = 1
    session.last_used = time.monotonic() - 10
    await app.frida.maintain()
    assert session.active and session.hooks == {session.id + ':app_logs'}
    await app.tools.invoke('app_logs', {**request, 'action': 'stop'})
    session.last_used = time.monotonic() - 10
    await app.frida.maintain()
    assert not session.active


async def test_debug_setup_reports_missing_and_preserves_existing(capture_app, monkeypatch):
    app, sdk = capture_app
    app.ssh._probe = AsyncMock(return_value={'frida_version': sdk.api.__version__, 'ios_version': '16.0'})
    app.debugger.lldb = '/usr/bin/lldb'
    monkeypatch.setattr(app.classdump, 'executable', lambda: None)
    result = await app.tools.invoke('debug_setup', {'device_id': 'test', 'bundle_id': BUNDLE})
    assert result.ok and result.data['versions_match']
    assert 'debugserver_device' in result.data['missing']
    assert result.data['next_actions'][0]['arguments']['action'] == 'install'
    assert not result.data['inspection_verified'] and sdk.attaches == 0
    app.ssh._probe.return_value = {'frida_version': sdk.api.__version__, 'debugserver': '/existing/debugserver'}
    app.ssh.invalidate_probe('test')
    app.ssh.upload = AsyncMock()
    already = await app.tools.invoke('debug_setup', {'device_id': 'test', 'bundle_id': BUNDLE, 'action': 'install'})
    assert already.ok and already.data['already_installed']
    app.ssh.upload.assert_not_awaited()


async def test_debug_setup_install_signs_and_invalidates_probe(capture_app, tmp_path):
    app, sdk = capture_app
    executable = tmp_path / 'debugserver'
    executable.write_bytes(ios_executable())
    first = {'ios_version': '16.0', 'frida_version': sdk.api.__version__, 'debugserver_profile': '/profile.plist', 'ldid': '/usr/bin/ldid'}
    installed = {**first, 'debugserver': '/var/jb/usr/bin/debugserver'}
    app.ssh._probe = AsyncMock(side_effect=[first, installed])
    app.ssh.upload = AsyncMock()
    app.ssh._run = AsyncMock(return_value={'exit_status': 0, 'stdout': 'debugserver-version', 'stderr': ''})
    result = await app.tools.invoke('debug_setup', {'device_id': 'test', 'bundle_id': BUNDLE, 'action': 'install', 'local_debugserver_path': str(executable)})
    assert result.ok and result.data['installed'] and not result.data['inspection_verified']
    assert app.ssh._probe.await_count == 2
    app.ssh.upload.assert_awaited_once()
    commands = [call.args[1] for call in app.ssh._run.await_args_list]
    assert any('test ! -e' in cmd for cmd in commands)
    assert any('-S/profile.plist' in cmd for cmd in commands)
    assert any('rm -f' in cmd for cmd in commands)


@pytest.mark.parametrize('cancel', [False, True])
async def test_lldb_session_forward_process_and_request_cleanup(capture_app, monkeypatch, cancel):
    app, _ = capture_app
    attached = await app.frida.attach('test', BUNDLE)
    app.ssh.probe = AsyncMock(return_value={'debugserver': '/debugserver'})
    app.debugger.lldb = '/host/lldb'
    remote_done = asyncio.Event()
    stdout, stderr = asyncio.StreamReader(), asyncio.StreamReader()
    stdout.feed_data(b'Listening on port 12345\n')
    stdout.feed_eof()
    stderr.feed_eof()
    remote = SimpleNamespace(stdout=stdout, stderr=stderr, exit_status=None, exit_signal=None,
        wait_closed=remote_done.wait, terminate=lambda: remote_done.set(), close=lambda: remote_done.set())
    closed = []
    listener = SimpleNamespace(get_port=lambda: 34567, close=lambda: closed.append(True), wait_closed=AsyncMock())
    connection = SimpleNamespace(create_process=AsyncMock(return_value=remote), forward_local_port=AsyncMock(return_value=listener))
    app.ssh.connect = AsyncMock(return_value=connection)
    app.ssh._run = AsyncMock(return_value={})
    process = SimpleNamespace(returncode=None, kill=lambda: setattr(process, 'returncode', -9), wait=AsyncMock())
    spawn = AsyncMock(return_value=process)
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', spawn)
    started = asyncio.Event()

    async def output(_):
        started.set()
        if cancel:
            await asyncio.Event().wait()
        return 'IOS_DEBUG_JSON:' + json.dumps({'backend': 'lldb', 'detached': True, 'threads': []}), ''

    app.debugger._output = output
    task = asyncio.create_task(app.debugger.inspect('test', attached['session_id'], {'mode': 'threads'}))
    await asyncio.wait_for(started.wait(), 2)
    if cancel:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    else:
        assert (await task)['detached']
    assert remote_done.is_set() and closed and process.returncode == -9
    assert not list(app.settings.state_dir.glob('lldb_*.json'))
    assert app.ssh._run.await_args.args[1] == 'kill -CONT 42'
    assert not app.frida.session('test', attached['session_id']).lock.locked()


def test_lldb_worker_detaches_even_when_remote_identity_changes():
    detached, deleted = [], []
    error = SimpleNamespace(Success=lambda: True)
    process = SimpleNamespace(IsValid=lambda: True, GetProcessID=lambda: 999,
        Detach=lambda keep_stopped: detached.append(keep_stopped) or error)
    target = SimpleNamespace(ConnectRemote=lambda *args: process)
    debugger = SimpleNamespace(SetAsync=lambda _: None, CreateTargetWithFileAndArch=lambda *args: target,
        DeleteTarget=lambda value: deleted.append(value))
    api = SimpleNamespace(SBError=lambda: error, SBListener=lambda _: None)
    result = inspect(debugger, {'pid': 42, 'url': 'connect://localhost:12345'}, api)
    assert 'identity changed' in result['error'] and result['detached']
    assert detached == [False] and deleted == [target]
