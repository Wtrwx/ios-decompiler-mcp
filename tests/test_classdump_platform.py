from __future__ import annotations

import sys
from pathlib import Path

from mcp.shared.memory import create_connected_server_and_client_session

from tests.test_automation import automated_app as automated_app
from tests.test_capture import BUNDLE


async def test_static_dump_cache_filters_invalidation_and_expiry(app, tmp_path):
    counter = tmp_path / 'calls'
    tool = tmp_path / 'classdumpc'
    tool.write_text(f'#!{sys.executable}\nfrom pathlib import Path\nimport sys\np=Path({str(counter)!r})\np.write_text(p.read_text()+"1" if p.exists() else "1")\nprint("@interface Fixture : NSObject\\n@end")\nassert sys.argv[sys.argv.index("-C")+1] == "^Fixture$"\n')
    tool.chmod(0o700)
    app.settings.classdumpc = tool
    binary = tmp_path / 'binary with spaces'
    binary.write_bytes(b'first-source')
    request = {'binary_path': str(binary), 'class_name': 'Fixture', 'preview_chars': 16}
    first = await app.tools.invoke('objc_dump', request)
    assert first.ok and first.data['backend'] == 'classdumpc'
    assert len(first.data['preview']) == 16 and first.data['preview_truncated']
    second = await app.tools.invoke('objc_dump', request)
    assert second.ok and second.data['reused'] and counter.read_text() == '1'
    binary.write_bytes(b'changed-source')
    changed = await app.tools.invoke('objc_dump', request)
    assert changed.ok and changed.data['source_sha256'] != first.data['source_sha256']
    assert counter.read_text() == '11'
    for key, (_, path, size) in list(app.classdump.cache.items()):
        app.classdump.cache[key] = (0, path, size)
    app.classdump.expire()
    assert not app.classdump.cache and not Path(first.data['local_path']).exists()


async def test_missing_classdumpc_and_invalid_source_are_actionable(app, tmp_path):
    app.settings.classdumpc = tmp_path / 'missing'
    source = tmp_path / 'binary'
    source.touch()
    missing = await app.tools.invoke('objc_dump', {'binary_path': str(source)})
    assert missing.error.code == 'UNAVAILABLE' and missing.error.details['component'] == 'classdumpc'
    invalid = await app.tools.invoke('objc_dump', {'binary_path': str(source), 'device_id': 'test'})
    assert invalid.error.code == 'INVALID_INPUT'


async def test_focused_catalog_retains_full_access_and_gateway_image(automated_app):
    app, sdk, server = automated_app
    async with create_connected_server_and_client_session(server) as client:
        focused = (await client.list_tools()).tools
        assert len(focused) == 19
        app.settings.tool_profile = 'full'
        full = (await client.list_tools()).tools
        assert len(full) >= 70 and len(str(focused)) < len(str(full))
        app.settings.tool_profile = 'focused'
        schema = await client.call_tool('platform_tool', {'name': 'objc_get_ivars', 'action': 'schema'})
        assert 'class_name' in schema.structuredContent['data']['inputSchema']['required']
        assert sdk.attaches == 0
        result = await client.call_tool('platform_tool', {'name': 'ui_capture', 'arguments': {
            'device_id': 'test', 'bundle_id': BUNDLE, 'mode': 'screenshot'}})
        assert not result.isError and len([item for item in result.content if item.type == 'image']) == 1
        denied = await client.call_tool('platform_tool', {'name': 'device_launch', 'arguments': {
            'device_id': 'test', 'bundle_id': BUNDLE}})
        assert denied.structuredContent['error']['code'] == 'APPROVAL_REQUIRED'
        recursive = await client.call_tool('platform_tool', {'name': 'platform_tool'})
        assert recursive.isError
