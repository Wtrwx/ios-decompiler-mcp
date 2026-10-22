"""Read-only real-device checks for automation assertions and instance values.

Does not perform UI mutations. Reports contain timing/counts,
not object contents, UI text or image payloads.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import time
from collections import Counter
from pathlib import Path
from typing import Any

from benchmark_capture import stats
from mcp.shared.memory import create_connected_server_and_client_session

from vesper.app import Application
from vesper.config import Settings
from vesper.server import create_server


async def verify(args: argparse.Namespace) -> None:
    settings = Settings.load(args.config)
    settings.state_dir = args.output.parent / (args.output.stem + '-state')
    app, counts = Application(settings), Counter()
    original = app.frida.rpc

    async def counted(*pos: Any, **kw: Any) -> Any:
        counts[pos[2]] += 1
        return await original(*pos, **kw)

    app.frida.rpc = counted  # type: ignore[method-assign]
    report: dict[str, Any] = {'passed': False, 'mutations_performed': False,
                            'client_scope': 'in-memory MCP SDK round trip; excludes stdio, model and viewer'}
    try:
        server = create_server(app)
        async with create_connected_server_and_client_session(server) as client:
            async def call(name: str, **kw: Any) -> Any:
                result = await client.call_tool(name, {'device_id': args.device, **kw})
                if result.isError:
                    raise RuntimeError(str(result.structuredContent['error']))
                return result

            capture = await call('ui_capture', bundle_id=args.bundle, mode='summary', limit=2)
            view_id = capture.structuredContent['data']['summary']['views'][0]['view_id']
            session_id = capture.structuredContent['data']['session_id']
            metadata = await call('objc_get_ivars', session_id=session_id, class_name='UIView', limit=100)
            fields = [row['name'] for row in metadata.structuredContent['data']['ivars']
                      if row['type_encoding'] in {'i', 'I', 's', 'S', 'q', 'Q', 'f', 'd', 'B', 'c', 'C'}]
            assert fields, 'Expected an observed UIView scalar ivar'
            field = fields[0]
            report['observed_scalar_field'] = field
            query = {'bundle_id': args.bundle, 'object_ids': [view_id], 'field_names': [field], 'limit': 1}
            result = await call('objc_query_instances', **query)
            value = result.structuredContent['data']['instances'][0]['values'][field]
            assert isinstance(value, (int, float)) or (isinstance(value, dict) and 'scalar' in value), 'Expected a concrete UIView scalar ivar'
            report['concrete_ivar_read'] = True
            heap = await call('objc_query_instances', bundle_id=args.bundle, class_name='UILabel',
                              field_names=[field], max_instances=3, limit=1)
            data = heap.structuredContent['data']
            assert data['total'] > 1 and 'unavailable' not in str(data['instances'][0]['values'][field])
            before = counts.copy()
            await call('objc_query_instances', bundle_id=args.bundle, **data['next_cursor'], limit=1)
            assert before == counts
            report['instance_paging_zero_rpc'] = True
            rows = await call('objc_query_instances', bundle_id=args.bundle,
                object_ids=[view_id, data['instances'][0]['object_id']], field_names=[field], limit=2)
            assert len(rows.structuredContent['data']['instances']) == 2
            report['mixed_handle_query'] = True
            batch = {'bundle_id': args.bundle, 'steps': [{'action': 'assert', 'target': {'view_id': view_id}},
                {'action': 'wait_for', 'target': {'view_id': view_id}, 'timeout_ms': 100, 'poll_ms': 50}]}
            checked = await call('ui_automate', **batch, after_capture='both', limit=2)
            assert checked.structuredContent['data']['completed']
            assert len([item for item in checked.content if item.type == 'image']) == 1
            report['read_only_batch_and_native_image'] = True
            for label, tool, request in [('selected_ivar_handle', 'objc_query_instances', query), ('two_read_only_steps', 'ui_automate', batch)]:
                samples = []
                for _ in range(args.samples):
                    started = time.perf_counter()
                    result = await call(tool, **request)
                    samples.append({'server_ms': result.structuredContent['elapsed_ms'],
                        'client_ms': (time.perf_counter() - started) * 1000,
                        'response_bytes': len(result.model_dump_json().encode())})
                    assert result.structuredContent['data']['session_id'] == session_id
                report[label] = {key: stats([sample[key] for sample in samples]) for key in samples[0]}
            report['rpc_counts'] = dict(counts)
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
    parser.add_argument('--samples', type=int, default=20)
    arguments = parser.parse_args()
    if arguments.samples < 1:
        parser.error('--samples must be positive')
    asyncio.run(verify(arguments))
