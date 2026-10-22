from __future__ import annotations

import asyncio
import hashlib
import shlex
import struct
import uuid
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from pydantic import Field

from vesper.app import Application
from vesper.core.errors import Code, MCPError
from vesper.core.registry import new_id
from vesper.tools.models import AppRequest


def verify_decrypted(path: Path, expected_uuid: str | None = None) -> dict[str, Any]:
    size = path.stat().st_size
    identifiers: list[int] = []
    identifier = None
    with path.open('rb') as stream:
        initial = stream.read(32)
        if len(initial) != 32 or initial[:4] != b'\xcf\xfa\xed\xfe':
            raise MCPError(Code.VERIFICATION_FAILED, 'Dump is not a thin ARM64 Mach-O')
        cpu, subtype, _, count, commands = struct.unpack_from('<5I', initial, 4)
        if cpu != 0x100000C or count > 4096 or commands > min(16 * 1024 * 1024, size - 32):
            raise MCPError(Code.VERIFICATION_FAILED, 'Invalid Mach-O command bounds')
        offset = 32
        for _ in range(count):
            stream.seek(offset)
            data = stream.read(24)
            if len(data) < 8:
                raise MCPError(Code.VERIFICATION_FAILED, 'Truncated Mach-O load command')
            command, length = struct.unpack_from('<II', data)
            if length < 8 or offset + length > 32 + commands:
                raise MCPError(Code.VERIFICATION_FAILED, 'Invalid Mach-O load command')
            if command in {0x21, 0x2C}:
                if length < 20 or len(data) < 20:
                    raise MCPError(Code.VERIFICATION_FAILED, 'Truncated encryption command')
                cryptoff, cryptsize, cryptid = struct.unpack_from('<III', data, 8)
                if cryptoff + cryptsize > size or cryptid != 0:
                    raise MCPError(Code.VERIFICATION_FAILED, 'Dump remains encrypted or has invalid encryption bounds')
                identifiers.append(cryptid)
            if command == 0x1B and length >= 24 and len(data) >= 24:
                identifier = str(uuid.UUID(bytes=data[8:24]))
            offset += length
    if expected_uuid and (not identifier or identifier.lower() != expected_uuid.lower()):
        raise MCPError(Code.IDENTITY_MISMATCH, 'Decrypted file UUID differs from the loaded image')
    return {'architecture': 'arm64e' if subtype & 0xFFFFFF == 2 else 'arm64', 'uuid': identifier,
        'cryptids': identifiers, 'decryption_verified': True}


class Decrypt(AppRequest):
    action: Literal['modules', 'dump'] = 'dump'
    module_name: str | None = Field(default=None, min_length=1, max_length=255)
    module_path: str | None = Field(default=None, min_length=1, max_length=4096)
    background: bool = True
    offset: int = Field(default=0, ge=0, le=1000000)
    limit: int = Field(default=30, ge=1, le=100)


def register(app: Application) -> None:
    async def work(request: Decrypt) -> dict[str, Any]:
        with app.frida.keepalive(request.device_id, request.bundle_id):
            attached = await app.frida.attach(request.device_id, request.bundle_id)
            session_id = attached['session_id']
            info = await app.frida.rpc(request.device_id, session_id, 'decrypt_modules')
            modules = info['modules']
            if request.action == 'modules':
                return {'session_id': session_id, 'modules': modules[request.offset:request.offset + request.limit],
                    'total': len(modules), 'main_module': info['main_module'],
                    'next_offset': request.offset + request.limit if request.offset + request.limit < len(modules) else None}
            if request.module_name and request.module_path:
                raise MCPError(Code.INVALID_INPUT, 'Select module_name or module_path')
            selected = [module for module in modules if
                module['path'] == request.module_path] if request.module_path else [
                module for module in modules if module['name'] == request.module_name] if request.module_name else [
                module for module in modules if module['path'] == info['main_module']]
            if len(selected) != 1:
                raise MCPError(Code.INVALID_INPUT, 'Select exactly one loaded app module; use action=modules')
            module = selected[0]
            token = new_id('decrypt')
            remote = info['dump_directory'].rstrip('/') + '/vesper-' + token + '.fid'
            directory = app.settings.state_dir / 'decrypted' / token
            directory.mkdir(parents=True, mode=0o700)
            local = directory / PurePosixPath(module['path']).name
            temporary = directory / 'transfer.part'
            connection = await app.ssh.connect(request.device_id)
            succeeded = False
            try:
                result = await app.frida.rpc(request.device_id, session_id, 'decrypt_module',
                    {'module_path': module['path'], 'dump_id': token, 'output_directory': info['dump_directory'], 'max_bytes': app.settings.max_decrypt_bytes})
                if result['remote_path'] != remote:
                    raise MCPError(Code.IDENTITY_MISMATCH, 'Unexpected decrypted file path')
                digest = hashlib.sha256()
                transferred = 0
                async with asyncio.timeout(app.settings.build_timeout), connection.start_sftp_client() as sftp:
                    attrs = await sftp.stat(remote)
                    if attrs.size is None or attrs.size > app.settings.max_decrypt_bytes:
                        raise MCPError(Code.LIMIT_EXCEEDED, 'Decrypted file exceeds max_decrypt_bytes')
                    async with sftp.open(remote, 'rb', encoding=None) as source:
                        with temporary.open('xb') as output:
                            temporary.chmod(0o600)
                            while data := await source.read(262144):
                                transferred += len(data)
                                if transferred > app.settings.max_decrypt_bytes:
                                    raise MCPError(Code.LIMIT_EXCEEDED, 'Decrypted transfer exceeded its bound')
                                output.write(data)
                                digest.update(data)
                    if transferred != attrs.size:
                        raise MCPError(Code.VERIFICATION_FAILED, 'Decrypted file size changed during transfer')
                metadata = verify_decrypted(temporary, result.get('image', {}).get('uuid'))
                temporary.replace(local)
                succeeded = True
                return {'session_id': session_id, 'backend': 'frida-ios-dump', 'upstream_commit': result['upstream_commit'],
                    'binary_path': str(local), 'module_path': module['path'], 'bytes': transferred,
                    'sha256': digest.hexdigest(), 'original_cryptid': result.get('original_cryptid'), **metadata,
                    'next': {'headers': 'objc_dump(binary_path=..., class_name=...)',
                        'disassembly': 'platform_tool(name=ida_open_binary, arguments={path: binary_path})'}}
            except TimeoutError as exc:
                raise MCPError(Code.TIMEOUT, 'Decrypted file transfer timed out') from exc
            finally:
                temporary.unlink(missing_ok=True)
                if not succeeded:
                    local.unlink(missing_ok=True)
                    directory.rmdir()
                # Also runs after cancelled/failed RPCs: the filename is known
                # before device work starts, and belongs only to this request.
                try:
                    await asyncio.shield(app.ssh._run(request.device_id, 'rm -f ' + shlex.quote(remote), timeout=5))
                except Exception:
                    pass

    async def decrypt(request: Decrypt) -> dict[str, Any]:
        app.permissions.device(request.device_id, request.bundle_id)
        if request.action == 'modules' or not request.background:
            return await work(request)
        return app.jobs.start('app_decrypt', lambda: work(request))

    app.tools.add('app_decrypt', Decrypt, decrypt, 'Decrypt one loaded app Mach-O using maintained frida-ios-dump code and the existing Frida/SSH session. Default main executable, background job; module_name/path selects an app framework. action=modules lists bounded loaded candidates without dumping. Returns verified cryptid=0/UUID/SHA-256 and binary_path for objc_dump or ida_open_binary; no IPA packaging or forced framework loading.', read_only=False)
