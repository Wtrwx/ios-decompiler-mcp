"""Alternate original/updated real-device capture benchmarks in bounded chunks."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path

from benchmark_capture import save, stats


def run(args: argparse.Namespace) -> None:
    root = Path(__file__).resolve().parents[1]
    variants = [('original', args.baseline_source, 'legacy' if args.scenario == 'cold' else 'session', None),
                ('binary', root / 'src', 'capture', 'binary')]
    if args.scenario == 'reuse':
        variants.append(('base64', root / 'src', 'capture', 'base64'))
    collected: dict[str, list] = {name: [] for name, _, _, _ in variants}
    counters: dict[str, Counter] = {name: Counter() for name in collected}
    hashes = {}
    for start in range(0, args.samples, args.chunk):
        size = min(args.chunk, args.samples - start)
        for name, source, chain, transport in variants:
            output = args.output / f'{name}-{start:03}.json'
            environment = dict(os.environ, VESPER_BENCH_PACKAGE='ios_decompiler_mcp' if name == 'original' else 'vesper', PYTHONPATH=os.pathsep.join(str(p.resolve()) for p in [args.frida_path, source] if p))
            command = [sys.executable, str(root / 'scripts/benchmark_capture.py'), '--config', str(args.config.resolve()),
                '--device', args.device, '--bundle', args.bundle, '--chain', chain, '--temperature', args.scenario,
                '--samples', str(size), '--quiet', '--output', str(output.resolve())]
            if args.scenario == 'cold':
                command.append('--fresh-server')
            if transport:
                command.extend(['--image-transport', transport])
            subprocess.run(command, env=environment, check=True, stdout=subprocess.DEVNULL)
            report = json.loads(output.read_text())
            successful = [sample for sample in report['samples'] if sample.get('ok')]
            collected[name].extend(successful)
            counters[name].update(report.get('backend_counts') or json.loads(output.with_suffix('.counters.json').read_text()))
            hashes[name] = report.get('agent_sha256')
            print(json.dumps({'variant': name, 'complete': len(collected[name]), 'requested': args.samples}), flush=True)
            if len(successful) != size:
                raise RuntimeError('Device benchmark incomplete; retain failed report and restore the connection')
    for name, samples in collected.items():
        summary = {key: stats([sum(call[key] for call in sample['calls']) for sample in samples])
                   for key in ['client_ms', 'server_ms', 'response_bytes']}
        summary['calls_per_sample'] = [len(sample['calls']) for sample in samples]
        if args.scenario == 'cold':
            summary['startup_to_first_result_ms'] = stats([sample['startup_to_first_result_ms'] for sample in samples])
        stages = [sample.get('screenshot_timings_ms', {}) for sample in samples]
        save(args.output / f'{name}.json', {'scenario': args.scenario, 'samples_requested': args.samples, 'samples': samples,
            'summary': summary, 'backend_counts': dict(counters[name]), 'agent_sha256': hashes[name],
            'stages_ms': {key: stats([sample[key] for sample in stages if key in sample]) for key in {key for sample in stages for key in sample}},
            'design': f'Alternating chunks of {args.chunk}; MCP stdio time excludes model/viewer. Setup excluded for reuse; each cold sample uses a new MCP process.'})
        print(json.dumps({'variant': name, 'summary': summary}), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--baseline-source', type=Path, required=True)
    parser.add_argument('--frida-path', type=Path)
    parser.add_argument('--device', default='iphone')
    parser.add_argument('--bundle', default='com.ss.iphone.ugc.Aweme')
    parser.add_argument('--scenario', choices=['cold', 'reuse'], default='cold')
    parser.add_argument('--samples', type=int, default=20)
    parser.add_argument('--chunk', type=int, default=5)
    parser.add_argument('--output', type=Path, required=True)
    arguments = parser.parse_args()
    if arguments.samples < 1 or arguments.chunk < 1:
        parser.error('--samples and --chunk must be positive')
    run(arguments)
