"""Read-only hardware verification of task capture, native images, paging and leases."""
from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

from mcp.shared.memory import create_connected_server_and_client_session

from vesper.app import Application
from vesper.config import Settings
from vesper.server import create_server


async def verify(args: argparse.Namespace) -> None:
    settings = Settings.load(args.config)
    settings.state_dir = args.output.parent / 'verify-capture-state'
    settings.snapshot_ttl = 60
    settings.object_handle_ttl = 1
    settings.session_idle_timeout = 60
    settings.maintenance_interval = .1
    app = Application(settings)
    counts: Counter[str] = Counter()
    original = app.frida.rpc

    async def counted(*pos: Any, **kw: Any) -> Any:
        counts[pos[2]] += 1
        return await original(*pos, **kw)

    app.frida.rpc = counted  # type: ignore[method-assign]
    report: dict[str, Any] = {'passed': False, 'text_capture': False}
    try:
        server = create_server(app)
        async with create_connected_server_and_client_session(server) as client:
            async def call(name: str, **kw: Any) -> Any:
                result = await client.call_tool(name, {'device_id': args.device, **kw})
                if result.isError:
                    raise RuntimeError(str(result.structuredContent))
                return result

            first = await call('ui_capture', bundle_id=args.bundle, mode='both', limit=1)
            data = first.structuredContent['data']
            session_id = data['session_id']
            images = [item for item in first.content if item.type == 'image']
            assert len(images) == 1 and images[0].mimeType == 'image/png'
            png = base64.b64decode(images[0].data)
            assert png == Path(data['screenshot']['local_path']).read_bytes()
            assert 'base64' not in str(first.structuredContent)
            report['image'] = {'sha256': hashlib.sha256(png).hexdigest(), 'png_bytes': len(png),
                               'pixel_width': int.from_bytes(png[16:20], 'big'), 'pixel_height': int.from_bytes(png[20:24], 'big')}
            report['summary_total'] = data['summary']['total']
            assert not any('text' in node or 'controller' in node for node in data['summary']['views'])
            before = counts.copy()
            page = await call('ui_snapshot', session_id=session_id, snapshot_id=data['summary']['snapshot_id'], offset=1, limit=10)
            assert counts == before and page.structuredContent['data']['snapshot_id'] == data['summary']['snapshot_id']
            report['paging_zero_device_rpc'] = True
            for _ in range(3):
                repeated = await call('ui_capture', bundle_id=args.bundle, mode='screenshot')
                assert repeated.structuredContent['data']['session_id'] == session_id
                assert repeated.structuredContent['data']['reused']
                assert len([item for item in repeated.content if item.type == 'image']) == 1
            report['same_session_for_consecutive_images'] = True
            app.snapshots.invalidate(session_id)
            await app.frida.rpc(args.device, session_id, 'release_leases')
            settings.snapshot_ttl = settings.object_handle_ttl = 1
            summary = await call('ui_capture', bundle_id=args.bundle, mode='summary')
            assert not any(item.type == 'image' for item in summary.content)
            before_release = await app.frida.rpc(args.device, session_id, 'release_leases')
            await asyncio.sleep(1.3)
            after_release = await app.frida.rpc(args.device, session_id, 'release_leases')
            report['object_counts'] = {'before_expiry': before_release['objects'], 'after_expiry': after_release['objects']}
            assert before_release['objects'] > 0 and after_release['objects'] == 0
            session = app.frida.sessions[session_id]
            settings.session_idle_timeout = 1
            for _ in range(40):
                if not session.active:
                    break
                await asyncio.sleep(.1)
            assert not session.active and session.reason == 'idle_timeout'
            assert not app.snapshots.entries
            report['idle_session_reclaimed'] = True
            report['capture_rpc_count'] = counts['capture']
            report['passed'] = True
    finally:
        await app.close()
        args.output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        args.output.write_text(json.dumps(report, indent=2) + '\n')
        args.output.chmod(0o600)
        print(json.dumps(report))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--device', required=True)
    parser.add_argument('--bundle', required=True)
    parser.add_argument('--output', type=Path, required=True)
    asyncio.run(verify(parser.parse_args()))
