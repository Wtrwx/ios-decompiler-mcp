from __future__ import annotations

import asyncio
import base64
import struct
import time
import zlib
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from mcp.shared.memory import create_connected_server_and_client_session

from tests.test_transports import Cancellable
from vesper.app import Application
from vesper.core.errors import Code, MCPError
from vesper.core.snapshots import SnapshotCache
from vesper.server import create_server

BUNDLE = 'dev.iosdecompiler.fixture'
def chunk(kind, data):
    return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data))


PNG = b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 0, 0, 0, 0)) + chunk(b'IDAT', zlib.compress(b'\0\0')) + chunk(b'IEND', b'')


class CaptureSDK:
    """Fake the SDK boundary; use production attach/RPC/tools/MCP paths."""
    def __init__(self):
        self.pid = 42
        self.attaches = 0
        self.enumerations = 0
        self.calls = []
        self.handles = []
        self.device_callbacks = {}
        self.identity_override = None
        self.binary = False
        self.sdk_device = SimpleNamespace(enumerate_applications=self.applications, attach=self.attach,
            on=lambda event, callback: self.device_callbacks.update({event: callback}))
        self.api = SimpleNamespace(__version__='17.24.3', Cancellable=Cancellable, get_device=lambda *a, **kw: self.sdk_device)

    def applications(self, **kw):
        self.enumerations += 1
        return [SimpleNamespace(identifier=BUNDLE, name='Fixture', pid=self.pid, parameters={})]

    def attach(self, pid):
        self.attaches += 1
        callbacks = {}
        handle = SimpleNamespace(is_detached=False)
        handle.on = lambda event, callback: callbacks.update({event: callback})
        handle.callbacks = callbacks
        handle.detach = lambda: setattr(handle, 'is_detached', True)
        handle.create_script = lambda *a, **kw: SimpleNamespace(on=lambda *a: None, load=lambda: None,
            unload=lambda: None, exports_sync=SimpleNamespace(dispatch=lambda method, args: self.dispatch(pid, method, args)))
        self.handles.append(handle)
        return handle

    def dispatch(self, pid, method, args):
        self.calls.append((method, args))
        if method == 'initialize':
            return self.identity_override or {'bundle_id': BUNDLE, 'pid': pid}
        if method == 'dispose':
            return {'disposed': True}
        if method in {'snapshot', 'find_views', 'capture'}:
            tree = {'views': [{'view_id': f'object_{i}', 'class_name': 'CustomView', 'frame': {'x': i}} for i in range(10)],
                    'captured_at': '2026-10-23T00:00:00Z', 'truncated': True, 'total_visited': 12}
            if method != 'capture':
                return tree
            result = {**({'summary': tree} if args['mode'] in {'summary', 'both'} else {}),
                      **({'screenshot': self.png()} if args['mode'] in {'screenshot', 'both'} else {})}
            return (result, PNG) if self.binary and args['mode'] != 'summary' else result
        if method == 'screenshot':
            return (self.png(), PNG) if self.binary else self.png()
        if method == 'hook_method':
            return {'hook_id': 'hook_1'}
        if method in {'unhook', 'release_leases'}:
            return {'ok': True}
        raise AssertionError(method)

    def png(self):
        return {**({} if self.binary else {'base64': base64.b64encode(PNG).decode()}), 'window_id': 'window_1'}


@pytest.fixture
async def capture_app(settings):
    app = Application(settings)
    create_server(app)
    sdk = CaptureSDK()
    app.frida._api = sdk.api
    app.ssh._probe = AsyncMock(return_value={'frida_version': '17.24.3'})
    try:
        yield app, sdk
    finally:
        await app.close()


async def test_capture_and_attach_reuse_skip_discovery_and_ssh(capture_app):
    app, sdk = capture_app
    ids = set()
    for _ in range(5):
        result = await app.tools.invoke('ui_capture', {'device_id': 'test', 'bundle_id': BUNDLE, 'mode': 'screenshot'})
        assert result.ok, result.error
        ids.add(result.data['session_id'])
    attached = await app.tools.invoke('frida_attach', {'device_id': 'test', 'bundle_id': BUNDLE})
    assert attached.ok and attached.data['reused']
    assert len(ids) == sdk.attaches == sdk.enumerations == app.ssh._probe.await_count == 1
    assert len([method for method, args in sdk.calls if method == 'capture']) == 5
    assert all(args['include_text'] is False for method, args in sdk.calls if method == 'capture')
    denied = await app.tools.invoke('ui_capture', {'device_id': 'test', 'bundle_id': 'not.allowed', 'mode': 'screenshot'})
    missing_mode = await app.tools.invoke('ui_capture', {'device_id': 'test', 'bundle_id': BUNDLE})
    assert denied.error.code == 'NOT_ALLOWED' and missing_mode.error.code == 'INVALID_INPUT'
    assert sdk.attaches == 1


async def test_process_change_gets_new_verified_session_and_clears_pages(capture_app):
    app, sdk = capture_app
    first = await app.tools.invoke('ui_capture', {'device_id': 'test', 'bundle_id': BUNDLE, 'mode': 'summary'})
    session = app.frida.sessions[first.data['session_id']]
    old_snapshot = first.data['summary']['snapshot_id']
    sdk.pid = 43
    wrong = await app.tools.invoke('frida_attach', {'device_id': 'test', 'bundle_id': BUNDLE, 'pid': 44})
    assert wrong.error.code == 'IDENTITY_MISMATCH' and session.active
    attached = await app.tools.invoke('frida_attach', {'device_id': 'test', 'bundle_id': BUNDLE, 'pid': 43})
    assert attached.ok and attached.data['pid'] == 43 and attached.data['session_id'] != session.id
    assert not session.active and old_snapshot not in app.snapshots.entries
    assert sdk.attaches == 2 and app.ssh._probe.await_count == 1
    # Also cover detach notification/liveness before a callback arrives.
    sdk.handles[-1].is_detached = True
    sdk.pid = 44
    fresh = await app.frida.attach('test', BUNDLE)
    assert fresh['pid'] == 44 and sdk.attaches == 3


async def test_cold_attach_checks_injected_identity(capture_app):
    app, sdk = capture_app
    sdk.identity_override = {'bundle_id': 'different.app', 'pid': 42}
    with pytest.raises(MCPError) as error:
        await app.frida.attach('test', BUNDLE)
    assert error.value.code == Code.IDENTITY_MISMATCH
    assert all(not session.active for session in app.frida.sessions.values())
    assert sdk.handles[0].is_detached


@pytest.mark.parametrize('tool', ['ui_snapshot', 'ui_find_views'])
async def test_immutable_pages_never_reenter_device_and_live_capture_refreshes(capture_app, tool):
    app, sdk = capture_app
    attached = await app.frida.attach('test', BUNDLE)
    request = {'device_id': 'test', 'session_id': attached['session_id']}
    first = await app.tools.invoke(tool, {**request, 'limit': 3})
    assert first.ok and first.data['truncated'] and first.data['captured_at']
    snapshot_id = first.data['snapshot_id']
    calls = len(sdk.calls)
    # Mutating a returned result must not mutate the serialized capture.
    first.data['views'][0]['frame']['x'] = -999
    again = await app.tools.invoke(tool, {**request, 'snapshot_id': snapshot_id, 'limit': 3})
    second = await app.tools.invoke(tool, {**request, **first.data['next_cursor'], 'limit': 3})
    assert again.data['views'][0]['frame']['x'] == 0
    assert second.data['views'][0]['view_id'] == 'object_3'
    assert len(sdk.calls) == calls
    live = await app.tools.invoke(tool, {**request, 'limit': 3})
    assert live.data['snapshot_id'] != snapshot_id and len(sdk.calls) == calls + 1
    mixed = await app.tools.invoke(tool, {**request, 'snapshot_id': snapshot_id, 'include_text': True})
    assert mixed.error.code == 'INVALID_INPUT'
    with pytest.raises(MCPError) as wrong:
        app.snapshots.page(snapshot_id, 'another-device', attached['session_id'], 0, 3)
    assert wrong.value.code == Code.NOT_ALLOWED


async def test_snapshot_ttl_eviction_byte_limit_and_session_invalidation(capture_app):
    app, sdk = capture_app
    app.settings.snapshot_max_count = 1
    attached = await app.frida.attach('test', BUNDLE)
    request = {'device_id': 'test', 'session_id': attached['session_id']}
    first = await app.tools.invoke('ui_snapshot', request)
    old = first.data['snapshot_id']
    second = await app.tools.invoke('ui_snapshot', request)
    assert old not in app.snapshots.entries and old in app.frida.pending_releases[attached['session_id']]
    current = second.data['snapshot_id']
    app.snapshots.entries[current] = replace(app.snapshots.entries[current], expires=time.monotonic() - 1)
    count = len(sdk.calls)
    expired = await app.tools.invoke('ui_snapshot', {**request, 'snapshot_id': current})
    assert expired.error.code == 'NOT_FOUND' and len(sdk.calls) == count
    assert app.snapshots.bytes == 0
    await app.frida.rpc('test', attached['session_id'], 'release_leases')
    assert {old, current} <= set(sdk.calls[-1][1]['_release_leases'])
    app.settings.snapshot_max_bytes = 1024
    cache = SnapshotCache(app.settings, app.frida.release_lease)
    with pytest.raises(MCPError):
        cache.store('too-big', 'test', attached['session_id'], {'views': ['x' * 2048]}, time.monotonic())
    assert not cache.entries and cache.bytes == 0
    third = await app.tools.invoke('ui_snapshot', request)
    assert third.ok
    app.frida.device_lost('test')
    assert not app.snapshots.entries and app.snapshots.bytes == 0 and not app.ssh.probes
    assert not app.frida.sessions[attached['session_id']].active


async def test_idle_reaper_preserves_rpc_hook_and_workflow(capture_app):
    app, sdk = capture_app
    app.settings.session_idle_timeout = 1
    attached = await app.frida.attach('test', BUNDLE)
    session = app.frida.sessions[attached['session_id']]
    session.in_flight = 1
    session.last_used = 0
    await app.frida.maintain()
    assert session.active
    session.in_flight = 0
    await app.frida.rpc('test', session.id, 'hook_method')
    session.last_used = 0
    await app.frida.maintain()
    assert session.active and session.hooks == {'hook_1'}
    await app.frida.rpc('test', session.id, 'unhook', {'hook_id': 'hook_1'})
    with app.frida.keepalive('test', BUNDLE):
        session.last_used = 0
        await app.frida.maintain()
        assert session.active
    session.last_used = 0
    await app.frida.maintain()
    assert not session.active and session.reason == 'idle_timeout' and sdk.handles[0].is_detached


async def test_pending_rpc_and_cancellation_cleanup(capture_app):
    app, sdk = capture_app
    app.settings.session_idle_timeout = 1
    attached = await app.frida.attach('test', BUNDLE)
    session = app.frida.sessions[attached['session_id']]
    await session.lock.acquire()
    task = asyncio.create_task(app.frida.rpc('test', session.id, 'screenshot'))
    await asyncio.sleep(0)
    session.last_used = 0
    await app.frida.maintain()
    assert session.active and session.in_flight == 1
    session.lock.release()
    # Cancel an RPC while its native worker is outstanding.
    started = asyncio.Event()
    original = app.frida._call

    async def blocked(fn, **kw):
        started.set()
        await asyncio.Future()

    app.frida._call = blocked
    await started.wait()
    app.frida._call = original
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    assert not session.active and session.in_flight == 0 and sdk.handles[0].is_detached


@pytest.mark.parametrize('mode, image_count', [('summary', 0), ('screenshot', 1), ('both', 1)])
@pytest.mark.parametrize('binary', [False, True])
async def test_capture_native_image_and_compact_client_compatibility(settings, mode, image_count, binary):
    app = Application(settings)
    sdk = CaptureSDK()
    sdk.binary = binary
    app.frida._api = sdk.api
    app.ssh._probe = AsyncMock(return_value={'frida_version': '17.24.3'})
    server = create_server(app)
    try:
        async with create_connected_server_and_client_session(server) as client:
            result = await client.call_tool('ui_capture', {'device_id': 'test', 'bundle_id': BUNDLE, 'mode': mode})
            assert not result.isError and result.structuredContent['ok']
            images = [item for item in result.content if item.type == 'image']
            assert len(images) == image_count
            if images:
                assert base64.b64decode(images[0].data) == PNG and images[0].mimeType == 'image/png'
                assert result.structuredContent['data']['screenshot']['local_path']
            text = ' '.join(item.text for item in result.content if item.type == 'text')
            assert len(text) < 150 and 'base64' not in text and 'views' not in text
            assert 'base64' not in str(result.structuredContent)
            app.settings.legacy_text_json = True
            legacy = await client.call_tool('server_status', {})
            assert '"data"' in legacy.content[0].text
    finally:
        await app.close()
