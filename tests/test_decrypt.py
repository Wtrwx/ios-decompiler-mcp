from __future__ import annotations

import asyncio
import io
import struct
import uuid
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from tests.test_capture import BUNDLE
from tests.test_capture import capture_app as capture_app
from vesper.core.errors import MCPError
from vesper.tools.decrypt import verify_decrypted


def image(cryptid=0):
    identifier = uuid.UUID('11223344-5566-7788-99aa-bbccddeeff00')
    return (struct.pack('<8I', 0xFEEDFACF, 0x100000C, 0, 2, 2, 48, 0, 0) +
        struct.pack('<6I', 0x2C, 24, 80, 4, cryptid, 0) +
        struct.pack('<2I', 0x1B, 24) + identifier.bytes + b'code')


def test_decryption_verification_rejects_unpatched_truncated_and_wrong_identity(tmp_path):
    path = tmp_path / 'binary'
    path.write_bytes(image())
    assert verify_decrypted(path)['cryptids'] == [0]
    for value, identity in [(image(1), None), (image()[:40], None), (image(), str(uuid.uuid4()))]:
        path.write_bytes(value)
        with pytest.raises(MCPError):
            verify_decrypted(path, identity)


@pytest.mark.parametrize('cancel', [False, True])
async def test_decrypt_transfer_identity_session_pin_and_cleanup(capture_app, cancel):
    app, sdk = capture_app
    original = sdk.dispatch
    data = image()
    identifier = verify_decrypted
    started = asyncio.Event()
    module_path = '/App/Fixture.app/Fixture'

    def dispatch(pid, method, args):
        if method == 'decrypt_modules':
            return {'modules': [{'path': module_path, 'name': 'Fixture', 'size': 4096}], 'main_module': module_path, 'dump_directory': '/app/tmp'}
        if method == 'decrypt_module':
            sdk.calls.append((method, args))
            return {'remote_path': '/app/tmp/vesper-' + args['dump_id'] + '.fid', 'module_path': module_path,
                'image': {'uuid': '11223344-5566-7788-99aa-bbccddeeff00'}, 'upstream_commit': 'pinned'}
        return original(pid, method, args)

    sdk.dispatch = dispatch
    source = io.BytesIO(data)

    async def read(size):
        started.set()
        if cancel:
            await asyncio.Event().wait()
        return source.read(size)

    @asynccontextmanager
    async def open_file(*args, **kwargs):
        yield SimpleNamespace(read=read)

    @asynccontextmanager
    async def client():
        yield SimpleNamespace(stat=AsyncMock(return_value=SimpleNamespace(size=len(data))), open=open_file)

    app.ssh.connect = AsyncMock(return_value=SimpleNamespace(start_sftp_client=client))
    app.ssh._run = AsyncMock(return_value={})
    result = await app.tools.invoke('app_decrypt', {'device_id': 'test', 'bundle_id': BUNDLE})
    assert result.ok and result.data['status'] == 'running'
    await asyncio.wait_for(started.wait(), 2)
    job_id = result.data['job_id']
    if cancel:
        assert app.frida.pins[('test', BUNDLE)]
        job = await app.jobs.cancel(job_id)
        assert job['status'] == 'cancelled'
        assert not list(app.settings.state_dir.rglob('transfer.part'))
    else:
        await asyncio.gather(*list(app.jobs.tasks.values()))
        job = app.registry.get(job_id, 'job')
        assert job['status'] == 'completed'
        artifact = job['result']
        assert artifact['decryption_verified'] and identifier(__import__('pathlib').Path(artifact['binary_path']))['cryptids'] == [0]
        assert sdk.attaches == 1
    assert app.ssh._run.await_args.args[1].startswith('rm -f /app/tmp/vesper-')
    assert not app.frida.pins
