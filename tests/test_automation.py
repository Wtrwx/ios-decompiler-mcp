from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from mcp.shared.memory import create_connected_server_and_client_session

from tests.test_capture import BUNDLE, PNG, CaptureSDK
from vesper.app import Application
from vesper.core.errors import Code, MCPError
from vesper.server import create_server


class AutomationSDK(CaptureSDK):
    def dispatch(self, pid, method, args):
        if method in {'automate', 'find_instances', 'inspect_objects', 'inspect_object'}:
            self.calls.append((method, args))
            if method == 'automate':
                result = {'steps': [{'action': step['action'], 'performed': True} for step in args['steps']], 'completed': True, 'elapsed_ms': 1}
                if args['after_capture'] in {'summary', 'both'}:
                    result['summary'] = {'views': [{'view_id': 'object_one', 'class_name': 'CustomView'}], 'truncated': False}
                if args['after_capture'] in {'screenshot', 'both'}:
                    result['screenshot'] = {}
                    return result, PNG
                return result
            rows = [{'object_id': f'process:object_{i}', 'class_name': 'Fixture', 'values': {'_count': i}} for i in range(8)]
            return {'instances': rows, 'limit_reached': True}
        return super().dispatch(pid, method, args)


@pytest.fixture
async def automated_app(settings):
    app = Application(settings)
    server = create_server(app)
    sdk = AutomationSDK()
    app.frida._api = sdk.api
    app.ssh._probe = AsyncMock(return_value={'frida_version': '17.24.3'})
    try:
        yield app, sdk, server
    finally:
        await app.close()


async def test_batch_executes_once_without_extra_round_trip_or_input_in_audit(automated_app):
    app, sdk, _ = automated_app
    request = {'device_id': 'test', 'bundle_id': BUNDLE, 'steps': [
        {'action': 'tap', 'target': {'accessibility_identifier': 'button'}},
        {'action': 'input_text', 'target': {'view_id': 'process:input'}, 'text': 'do-not-log-this'},
        {'action': 'back'},
    ]}
    result = await app.tools.invoke('ui_automate', request)
    assert result.ok and result.data['completed'] and sdk.attaches == 1
    assert len([name for name, _ in sdk.calls if name == 'automate']) == 1
    assert app.registry.db.execute('SELECT count(*) FROM approvals').fetchone()[0] == 0
    assert 'do-not-log-this' not in str(result)
    assert 'do-not-log-this' not in str(app.registry.db.execute('SELECT * FROM audit').fetchall())


async def test_batch_native_image_and_snapshot_share_one_device_rpc(automated_app):
    app, sdk, server = automated_app
    request = {'device_id': 'test', 'bundle_id': BUNDLE, 'steps': [{'action': 'back'}], 'after_capture': 'both'}
    async with create_connected_server_and_client_session(server) as client:
        result = await client.call_tool('ui_automate', request)
        assert not result.isError
        assert len([item for item in result.content if item.type == 'image']) == 1
        assert len(result.content[0].text) < 100 and 'base64' not in str(result.structuredContent)
        data = result.structuredContent['data']
        assert data['summary']['snapshot_id'] in app.snapshots.entries
    assert len([name for name, _ in sdk.calls if name == 'automate']) == 1


async def test_batch_validation_and_uncertain_outcome_never_retries(automated_app):
    app, sdk, _ = automated_app
    base = {'device_id': 'test', 'bundle_id': BUNDLE}
    for steps in [[], [{'action': 'tap', 'target': {'x': 1}}], [{'action': 'tap', 'target': {'view_id': 'x', 'text': 'y'}}],
                  [{'action': 'wait_for', 'target': {'class_name': 'UIView'}, 'timeout_ms': 5000}] * 3]:
        invalid = await app.tools.invoke('ui_automate', {**base, 'steps': steps})
        assert invalid.error.code == 'INVALID_INPUT'
    request = {**base, 'steps': [{'action': 'back'}]}
    original = app.frida.rpc

    async def timeout(*args, **kwargs):
        if args[2] == 'automate':
            raise MCPError(Code.TIMEOUT, 'Outcome uncertain')
        return await original(*args, **kwargs)

    app.frida.rpc = AsyncMock(side_effect=timeout)
    failed = await app.tools.invoke('ui_automate', request)
    assert failed.error.code == 'TIMEOUT' and app.frida.rpc.await_count == sdk.attaches == 1


async def test_instance_query_reuses_session_and_pages_never_rescan(automated_app):
    app, sdk, _ = automated_app
    base = {'device_id': 'test', 'bundle_id': BUNDLE}
    first = await app.tools.invoke('objc_query_instances', {**base, 'class_name': 'Fixture', 'field_names': ['_count'], 'limit': 2})
    assert first.ok and 'views' not in first.data
    assert first.data['instances'][0]['values']['_count'] == 0
    snapshot_id = first.data['snapshot_id']
    count = len(sdk.calls)
    second = await app.tools.invoke('objc_query_instances', {**base, **first.data['next_cursor'], 'limit': 2})
    assert second.ok and second.data['instances'][0]['values']['_count'] == 2 and len(sdk.calls) == count
    changed = await app.tools.invoke('objc_query_instances', {**base, 'snapshot_id': snapshot_id, 'field_names': ['_other']})
    assert changed.error.code == 'INVALID_INPUT'
    app.settings.devices['test'].allowed_apps.append('another.app')
    wrong = await app.tools.invoke('objc_query_instances', {**base, 'bundle_id': 'another.app', 'snapshot_id': snapshot_id})
    assert wrong.error.code == 'NOT_ALLOWED' and len(sdk.calls) == count
    direct = await app.tools.invoke('objc_query_instances', {**base, 'object_ids': [first.data['instances'][0]['object_id']], 'field_names': ['_count']})
    assert direct.ok and sdk.attaches == 1
    assert sdk.calls[-1][0] == 'inspect_objects' and sdk.calls[-1][1]['_input_handles']
    app.frida.sessions[first.data['session_id']].invalidate('process_exit', app.registry)
    assert not app.snapshots.entries


async def test_instance_query_requires_a_bounded_source(automated_app):
    app, _, _ = automated_app
    base = {'device_id': 'test', 'bundle_id': BUNDLE}
    for invalid in [{}, {'class_name': 'Fixture', 'object_ids': ['object']}, {'object_ids': []},
                    {'class_name': 'Fixture', 'field_names': ['a' * 256]}, {'class_name': 'Fixture', 'max_depth': 4}]:
        result = await app.tools.invoke('objc_query_instances', {**base, **invalid})
        assert result.error.code == 'INVALID_INPUT'


async def test_batch_revalidates_a_changed_process_and_rejects_another_app(automated_app):
    app, sdk, _ = automated_app
    request = {'device_id': 'test', 'bundle_id': BUNDLE, 'steps': [{'action': 'back'}]}
    first = await app.tools.invoke('ui_automate', request)
    sdk.pid = 43
    sdk.handles[0].is_detached = True
    changed = await app.tools.invoke('ui_automate', request)
    assert first.ok and changed.ok and sdk.attaches == 2
    assert first.data['session_id'] != changed.data['session_id']
    denied = await app.tools.invoke('ui_automate', {**request, 'bundle_id': 'another.app'})
    assert denied.error.code == 'NOT_ALLOWED' and sdk.attaches == 2
