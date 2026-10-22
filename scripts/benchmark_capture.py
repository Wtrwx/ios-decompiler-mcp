"""Measure real MCP stdio round trips; never serialize images or UI text to reports.

Run the same script against the baseline and updated source trees. The server
uses an isolated state directory, never launches/restarts an app, and only
targets the configured allowlist. Client time excludes model and viewer time.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib
import json
import math
import os
import sys
import time
from collections import Counter
from importlib.resources import files
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server.stdio import stdio_server

# Only the benchmark runner loads the historical package to compare old code.
PACKAGE = os.environ.get("VESPER_BENCH_PACKAGE", "vesper")
Application = importlib.import_module(PACKAGE + ".app").Application
Settings = importlib.import_module(PACKAGE + ".config").Settings
create_server = importlib.import_module(PACKAGE + ".server").create_server


def save(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(json.dumps(data, indent=2) + "\n")
    path.chmod(0o600)


async def serve(args: argparse.Namespace) -> None:
    settings = Settings.load(args.config)
    settings.state_dir = args.output.parent / (args.output.stem + "-state")
    if args.image_transport:
        settings.screenshot_transport = args.image_transport
    app = Application(settings)
    counts: Counter[str] = Counter()
    created: set[str] = set()
    attach = app.frida.attach

    async def counted_attach(*pos: Any, **kw: Any) -> Any:
        result = await attach(*pos, **kw)
        created.add(result['session_id'])
        return result

    app.frida.attach = counted_attach  # type: ignore[method-assign]
    for owner, method, label in [(app.ssh, "_run", "ssh_commands"), (app.frida, "applications", "app_enumerations"), (app.frida, "rpc", "rpc")]:
        original = getattr(owner, method)

        def wrapper(fn: Any, key: str) -> Any:
            async def invoke(*pos: Any, **kw: Any) -> Any:
                counts[key] += 1
                if key == "rpc":
                    counts["rpc_" + pos[2]] += 1
                return await fn(*pos, **kw)
            return invoke

        setattr(owner, method, wrapper(original, label))
    try:
        server = create_server(app)
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())
    finally:
        counts["sessions_created"] = len(created)
        await app.close()
        save(args.output.with_suffix(".counters.json"), dict(counts))


def stats(values: list[float]) -> dict[str, Any]:
    ordered = sorted(values)
    if not ordered:
        return {"n": 0}
    return {"n": len(values), "min": ordered[0], "mean": sum(values) / len(values),
            "p50": ordered[math.ceil(len(values) * .5) - 1],
            "p95": ordered[math.ceil(len(values) * .95) - 1] if len(values) >= 20 else None}


async def benchmark(args: argparse.Namespace) -> None:
    report: dict[str, Any] = {"chain": args.chain, "temperature": args.temperature, "samples_requested": args.samples,
                              "units": "milliseconds and UTF-8 JSON result bytes (includes native image base64)",
                              "client_scope": "MCP stdio round trip; excludes model scheduling and viewer display", "samples": []}
    report['agent_sha256'] = hashlib.sha256(files(PACKAGE).joinpath('assets/agent.js').read_bytes()).hexdigest()
    parameters = StdioServerParameters(command=sys.executable,
        args=[str(Path(__file__).resolve()), "--serve", "--config", str(args.config.resolve()), "--output", str(args.output.resolve()),
              *(['--image-transport', args.image_transport] if args.image_transport else [])],
        env=dict(os.environ))
    session_id = None
    seen: set[str] = set()
    startup = time.perf_counter()
    async with stdio_client(parameters) as (read, write):
        async with ClientSession(read, write) as client:
            begin = time.perf_counter()
            await client.initialize()
            report["initialize_client_ms"] = (time.perf_counter() - begin) * 1000
            if args.temperature == 'reuse' and args.chain in {'capture', 'session'}:
                tool = 'ui_capture' if args.chain == 'capture' else 'frida_attach'
                setup = await client.call_tool(tool, {'device_id': args.device, 'bundle_id': args.bundle,
                    **({'mode': 'screenshot'} if args.chain == 'capture' else {})})
                if setup.isError:
                    report['setup_error'] = (setup.structuredContent or {}).get('error')
                    save(args.output, report)
                    print(json.dumps({'path': str(args.output), 'setup_failed': True}))
                    return
                session_id = setup.structuredContent['data']['session_id']
                seen.add(session_id)
                report['setup_server_ms'] = setup.structuredContent['elapsed_ms']
            for index in range(args.samples):
                sample: dict[str, Any] = {"index": index, "calls": []}
                report["samples"].append(sample)

                async def call(name: str, sample: dict[str, Any] = sample, **kw: Any) -> dict[str, Any]:
                    start = time.perf_counter()
                    result = await client.call_tool(name, {"device_id": args.device, **kw})
                    elapsed = (time.perf_counter() - start) * 1000
                    structured = result.structuredContent or {}
                    sample["calls"].append({"tool": name, "client_ms": elapsed, "server_ms": structured.get("elapsed_ms"),
                                             "response_bytes": len(result.model_dump_json().encode()), "ok": not result.isError})
                    if result.isError:
                        sample["error"] = structured.get("error")
                        raise RuntimeError("Benchmark tool failed: " + name)
                    data = structured["data"]
                    image = data.get("screenshot", data)
                    if image.get("timings_ms"):
                        sample["screenshot_timings_ms"] = image["timings_ms"]
                    if image.get('local_path'):
                        png = Path(image['local_path']).read_bytes()
                        sample['png'] = {'bytes': len(png), 'sha256': hashlib.sha256(png).hexdigest(),
                                         'pixel_width': int.from_bytes(png[16:20], 'big'), 'pixel_height': int.from_bytes(png[20:24], 'big')}
                    if data.get("session_id"):
                        seen.add(data["session_id"])
                    return data

                try:
                    if args.chain == "legacy":
                        await call("device_list_apps")
                        attached = await call("frida_attach", bundle_id=args.bundle)
                        session_id = attached["session_id"]
                        await call("ui_screenshot", session_id=session_id)
                        await call("frida_detach", session_id=session_id)
                        session_id = None
                    elif args.chain == "capture":
                        if args.temperature == "cold" and session_id:
                            # Deliberately cold session; cleanup isn't part of the one-call capture.
                            await client.call_tool("frida_detach", {"device_id": args.device, "session_id": session_id})
                        data = await call("ui_capture", bundle_id=args.bundle, mode="screenshot")
                        session_id = data["session_id"]
                    elif args.chain == 'session':
                        await call('ui_screenshot', session_id=session_id)
                    else:
                        if not session_id:
                            attached = await call("frida_attach", bundle_id=args.bundle)
                            session_id = attached["session_id"]
                        first = await call("ui_snapshot", session_id=session_id, limit=1, include_text=False)
                        offset = first.get("next_offset")
                        for _ in range(4):
                            if offset is None:
                                break
                            page_args = {"snapshot_id": first["snapshot_id"]} if "snapshot_id" in first else {}
                            page = await call("ui_snapshot", session_id=session_id, limit=1, offset=offset, **page_args)
                            offset = page.get("next_offset")
                    sample["ok"] = True
                    if index == 0:
                        report['startup_to_first_result_ms'] = (time.perf_counter() - startup) * 1000
                except RuntimeError:
                    sample["ok"] = False
                    break
                finally:
                    save(args.output, report)
            if session_id:
                await client.call_tool("frida_detach", {"device_id": args.device, "session_id": session_id})
    successful = [sample for sample in report["samples"] if sample.get("ok")]
    report["sessions_observed"] = len(seen)
    report["summary"] = {key: stats([sum(call[key] for call in sample["calls"]) for sample in successful])
                         for key in ["client_ms", "server_ms", "response_bytes"]}
    report["summary"]["calls_per_sample"] = [len(sample["calls"]) for sample in successful]
    stages = [sample.get('screenshot_timings_ms', {}) for sample in successful]
    report['stages_ms'] = {key: stats([stage[key] for stage in stages if key in stage]) for key in {key for stage in stages for key in stage}}
    save(args.output, report)
    if not args.quiet:
        print(json.dumps({"path": str(args.output), "summary": report["summary"], "sessions_observed": len(seen),
                          "failures": len(report["samples"]) - len(successful)}, ensure_ascii=False))


async def fresh_servers(args: argparse.Namespace) -> None:
    samples, counters, startups = [], Counter(), []
    for index in range(args.samples):
        once = argparse.Namespace(**vars(args))
        once.samples, once.quiet, once.temperature = 1, True, 'cold'
        once.output = args.output.parent / (args.output.stem + '-samples') / f'{index:02}.json'
        await benchmark(once)
        report = json.loads(once.output.read_text())
        if not report['samples'] or not report['samples'][0].get('ok'):
            break
        samples.append(report['samples'][0])
        samples[-1]['startup_to_first_result_ms'] = report['startup_to_first_result_ms']
        startups.append(report['startup_to_first_result_ms'])
        counters.update(json.loads(once.output.with_suffix('.counters.json').read_text()))
    summary = {key: stats([sum(call[key] for call in sample['calls']) for sample in samples])
               for key in ['client_ms', 'server_ms', 'response_bytes']}
    summary['startup_to_first_result_ms'] = stats(startups)
    save(args.output, {'temperature': 'fresh_server', 'chain': args.chain, 'samples_requested': args.samples,
                       'samples': samples, 'summary': summary, 'backend_counts': dict(counters),
                       'agent_sha256': report.get('agent_sha256'),
                       'client_scope': 'stdio round trip; startup_to_first_result includes process launch + MCP initialize, excludes model/viewer'})
    print(json.dumps({'path': str(args.output), 'summary': summary}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--device", default="iphone")
    parser.add_argument("--bundle", default="com.ss.iphone.ugc.Aweme")
    parser.add_argument("--chain", choices=["legacy", "capture", "pages", "session"], default="capture")
    parser.add_argument("--temperature", choices=["cold", "reuse"], default="reuse")
    parser.add_argument("--samples", type=int, default=20)
    parser.add_argument('--fresh-server', action='store_true', help='Use a new MCP server process for every sample, without SSH or Frida caches')
    parser.add_argument('--quiet', action='store_true')
    parser.add_argument('--image-transport', choices=['binary', 'base64'], help='Override transport in the updated server for controlled encoding comparisons')
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    if arguments.samples < 1:
        parser.error('--samples must be positive')
    asyncio.run(serve(arguments) if arguments.serve else fresh_servers(arguments) if arguments.fresh_server else benchmark(arguments))
