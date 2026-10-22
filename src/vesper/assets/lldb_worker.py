"""Loaded by LLDB's embedded Python, never by the MCP interpreter."""
from __future__ import annotations

import json
import os
from typing import Any


def inspect(debugger: Any, request: dict[str, Any], api: Any) -> dict[str, Any]:
    debugger.SetAsync(False)
    target = debugger.CreateTargetWithFileAndArch(None, 'arm64-apple-ios')
    error = api.SBError()
    process = None
    result: dict[str, Any] = {'backend': 'lldb', 'consistent_stop': True, 'detached': False}
    try:
        process = target.ConnectRemote(api.SBListener('vesper'), request['url'], 'gdb-remote', error)
        if not error.Success() or not process.IsValid():
            raise RuntimeError(str(error))
        if process.GetProcessID() != request['pid']:
            raise RuntimeError('Remote debugger process identity changed')
        if process.GetState() != api.eStateStopped:
            raise RuntimeError('Remote debugger did not stop the selected process')
        if request.get('thread_id') is not None:
            selected = process.GetThreadByID(request['thread_id'])
            if not selected.IsValid():
                raise RuntimeError('Selected thread is no longer present')
            threads = [selected]
        else:
            threads = [process.GetThreadAtIndex(index) for index in range(min(process.GetNumThreads(), request['max_threads']))]
        rows = []
        for thread in threads:
            row: dict[str, Any] = {'thread_id': thread.GetThreadID(), 'name': thread.GetName()}
            if request['mode'] == 'backtrace':
                row['frames'] = [{'index': i, 'address': hex(frame.GetPC()),
                    **({'symbol': (frame.GetFunctionName() or '')[:512]} if request['symbols'] else {})}
                    for i in range(min(thread.GetNumFrames(), request['max_frames']))
                    for frame in [thread.GetFrameAtIndex(i)]]
            if request['mode'] in {'registers', 'locals'}:
                frame = thread.GetFrameAtIndex(request['frame_index'])
                if not frame.IsValid():
                    row['unavailable'] = 'Requested frame is not present'
                elif request['mode'] == 'registers':
                    names = request['register_names'] or ['pc', 'sp', 'fp', 'lr']
                    row['registers'] = {name: frame.FindRegister(name).GetValue() for name in names}
                else:
                    # Read existing SBValues only: no expressions, synthetic
                    # providers, summaries or description/getter execution.
                    values = frame.GetVariables(True, True, False, True)
                    variables = []
                    for index in range(min(values.GetSize(), request['max_variables'])):
                        value = values.GetValueAtIndex(index)
                        value.SetPreferSyntheticValue(False)
                        variables.append({'name': value.GetName(), 'type': value.GetTypeName(),
                            'value': (value.GetValue() or '')[:512]})
                    row['variables'] = variables
                    row['truncated'] = values.GetSize() > len(variables)
            rows.append(row)
        result.update(pid=process.GetProcessID(), threads=rows, observed=True)
    except Exception as exc:
        result['error'] = str(exc)[:1024]
    finally:
        if process is not None and process.IsValid():
            result['detached'] = process.Detach(False).Success()
        debugger.DeleteTarget(target)
    return result


def __lldb_init_module(debugger: Any, _: Any) -> None:
    import lldb
    with open(os.environ['VESPER_LLDB_REQUEST'], encoding='utf-8') as stream:
        request = json.load(stream)
    print('IOS_DEBUG_JSON:' + json.dumps(inspect(debugger, request, lldb), separators=(',', ':')))
