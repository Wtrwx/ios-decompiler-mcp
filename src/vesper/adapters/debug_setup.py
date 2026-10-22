from __future__ import annotations

import asyncio
import contextlib
import hashlib
import os
import shlex
import shutil
import struct
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any

from vesper.core.errors import Code, MCPError
from vesper.core.registry import new_id

if TYPE_CHECKING:
    from vesper.app import Application


def validate_debugserver(path: Path) -> str:
    """Accept an ARM64 iOS executable, including Apple's universal DDI binary."""
    if not path.is_file() or path.stat().st_size > 16 * 1024 * 1024:
        raise MCPError(Code.INVALID_INPUT, 'Provide a debugserver executable of at most 16 MiB')
    data = path.read_bytes()
    slices = [data]
    if data[:4] == b'\xca\xfe\xba\xbe' and len(data) >= 8:
        count = struct.unpack_from('>I', data, 4)[0]
        if count > 16 or 8 + count * 20 > len(data):
            raise MCPError(Code.INVALID_INPUT, 'Invalid universal Mach-O header')
        slices = []
        for index in range(count):
            offset, size = struct.unpack_from('>II', data, 8 + index * 20 + 8)
            if offset + size <= len(data):
                slices.append(data[offset:offset + size])
    for image in slices:
        if len(image) < 32 or image[:4] != b'\xcf\xfa\xed\xfe':
            continue
        cpu, _, kind, count = struct.unpack_from('<IIII', image, 4)
        if cpu != 0x100000C or kind != 2 or count > 4096:
            continue
        offset = 32
        for _ in range(count):
            if offset + 8 > len(image):
                break
            command, size = struct.unpack_from('<II', image, offset)
            if size < 8 or offset + size > len(image):
                break
            if command == 0x25 or (command == 0x32 and size >= 24 and struct.unpack_from('<I', image, offset + 8)[0] == 2):
                return hashlib.sha256(data).hexdigest()
            offset += size
    raise MCPError(Code.INVALID_INPUT, 'debugserver must be a Mach-O ARM64 iOS executable, not the macOS host debugserver')


class DebugSetup:
    def __init__(self, app: Application):
        self.app = app
        self.lock = asyncio.Lock()

    async def check(self, device_id: str, bundle_id: str) -> dict[str, Any]:
        capabilities = await self.app.debugger.capabilities(device_id)
        probe = await self.app.ssh.probe(device_id)
        try:
            host_version = self.app.frida.api.__version__
        except MCPError:
            host_version = None
        components = {
            'frida_host': {'installed': host_version is not None, 'version': host_version,
                'install_hint': 'Install vesper[device] in the MCP server Python environment; match the device Frida version'},
            'frida_server': {'installed': bool(probe.get('frida_version')), 'version': probe.get('frida_version'),
                'install_hint': 'Use the existing device Frida deployment and restore its configured SSH/USB forwarding'},
            'lldb_host': {'installed': bool(capabilities['host_lldb']), 'path': capabilities['host_lldb'],
                'install_hint': 'Install Xcode/Command Line Tools on macOS, or LLVM LLDB on the host'},
            'debugserver_device': {'installed': bool(capabilities['device_debugserver']), 'path': capabilities['device_debugserver'],
                'install_hint': 'Call debug_setup(action=install); uses a matching local Xcode iOS DeveloperDiskImage or local_debugserver_path'},
            'classdumpc_host': {'installed': bool(self.app.classdump.executable()), 'path': self.app.classdump.executable(),
                'install_hint': 'Install host classdumpc or configure its absolute classdumpc path; only required for static header dumping'},
        }
        missing = [name for name, value in components.items() if not value['installed']]
        actions: list[dict[str, Any]] = []
        if 'debugserver_device' in missing:
            actions.append({'tool': 'debug_setup', 'arguments': {'device_id': device_id, 'bundle_id': bundle_id, 'action': 'install'}})
        versions_match = host_version == probe.get('frida_version') if host_version else False
        return {'ready': not any(name != 'classdumpc_host' for name in missing) and versions_match,
                'available_backends': {'frida': bool(host_version and versions_match),
                    'lldb': bool(capabilities['lldb']), 'classdumpc': bool(self.app.classdump.executable())},
                'inspection_verified': False, 'components': components, 'missing': missing, 'next_actions': actions,
                'agent_instruction': 'Install missing components before retrying the selected backend; follow next_actions and install_hint. Do not report debugging success until an inspection succeeds.' if missing else None,
                'versions_match': versions_match,
                'version_hint': None if versions_match else 'Match the imported host Frida version to the device server before attaching.'}

    async def command(self, *arguments: str) -> tuple[int, str, str]:
        process = await asyncio.create_subprocess_exec(*arguments, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            out, err = await self.app.debugger._output(process)
            return process.returncode or 0, out, err
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()

    @asynccontextmanager
    async def source(self, version: str, provided: Path | None) -> AsyncIterator[Path]:
        if provided:
            yield self.app.permissions.local_path(provided, must_exist=True)
            return
        if not shutil.which('hdiutil'):
            raise MCPError(Code.UNAVAILABLE, 'Provide local_debugserver_path; automatic extraction requires macOS hdiutil and a matching Xcode DeveloperDiskImage')
        developer = Path(os.environ.get('DEVELOPER_DIR', '/Applications/Xcode.app/Contents/Developer'))
        support = developer / 'Platforms/iPhoneOS.platform/DeviceSupport'
        major_minor = '.'.join(version.split('.')[:2])
        images = sorted(path for path in support.glob(major_minor + '*/DeveloperDiskImage.dmg')
                        if path.parent.name == major_minor or path.parent.name.startswith(major_minor + ' '))
        if not images:
            raise MCPError(Code.UNAVAILABLE, 'Matching Xcode DeveloperDiskImage is missing; install the iOS platform support or provide an extracted local_debugserver_path', ios_version=version)
        scratch = self.app.settings.state_dir / 'components' / new_id('ddi')
        mount = scratch / 'disk'
        mount.mkdir(parents=True, mode=0o700)
        mounted = False
        try:
            status, _, error = await self.command('hdiutil', 'attach', '-readonly', '-nobrowse', '-mountpoint', str(mount), str(images[0]))
            if status:
                raise MCPError(Code.UNAVAILABLE, 'Could not mount the local developer image', diagnostic=error[-1024:])
            mounted = True
            local = scratch / 'debugserver'
            source = mount / 'usr/bin/debugserver'
            if not source.is_file():
                raise MCPError(Code.UNAVAILABLE, 'This developer image does not contain debugserver; provide local_debugserver_path from compatible Apple device support')
            shutil.copyfile(source, local)
            local.chmod(0o600)
            yield local
        finally:
            if mounted:
                with contextlib.suppress(Exception):
                    status, _, _ = await self.command('hdiutil', 'detach', str(mount))
                    mounted = status != 0
            if not mounted:
                shutil.rmtree(scratch, ignore_errors=True)

    async def install(self, device_id: str, bundle_id: str, source: Path | None, *, repair: bool = False) -> dict[str, Any]:
        async with self.lock:
            probe = await self.app.ssh.probe(device_id)
            existing = probe.get('debugserver')
            if existing and not repair:
                return {'installed': False, 'already_installed': True, **await self.check(device_id, bundle_id)}
            installed: dict[str, Any] = {}
            destination = self.app.settings.devices[device_id].debugserver_path or ((self.app.settings.devices[device_id].jailbreak_prefix or '/var/jb') + '/usr/bin/debugserver')
            if not existing:
                async with self.source(probe['ios_version'], source) as executable:
                    digest = validate_debugserver(executable)
                    stage = self.app.settings.devices[device_id].staging_directory + '/' + new_id('debugserver')
                    try:
                        await self.app.ssh.upload(device_id, executable, stage, expected_sha256=digest)
                        command = 'test ! -e ' + shlex.quote(destination) + ' && install -m 0755 ' + shlex.quote(stage) + ' ' + shlex.quote(destination)
                        result = await self.app.ssh._run(device_id, command)
                        if result['exit_status']:
                            raise MCPError(Code.UNAVAILABLE, 'Could not install device debugserver', diagnostic=result['stderr'][-1024:])
                        installed = {'source_sha256': digest, 'bytes': executable.stat().st_size}
                    finally:
                        with contextlib.suppress(Exception):
                            await self.app.ssh._run(device_id, 'rm -f ' + shlex.quote(stage))
            else:
                destination = existing
            # Reuse a device-provided jailbreak signing profile when present.
            # The Apple image remains unchanged; only the installed copy is signed.
            if probe.get('debugserver_profile') and probe.get('ldid'):
                result = await self.app.ssh._run(device_id, shlex.quote(probe['ldid']) + ' ' + shlex.quote('-S' + probe['debugserver_profile']) + ' ' + shlex.quote(destination))
                if result['exit_status']:
                    raise MCPError(Code.UNAVAILABLE, 'Device debugserver signing failed', diagnostic=result['stderr'][-1024:])
                installed['signing_profile'] = probe['debugserver_profile']
            result = await self.app.ssh._run(device_id, shlex.quote(destination) + ' --version')
            self.app.ssh.invalidate_probe(device_id)
            if result['exit_status']:
                raise MCPError(Code.UNAVAILABLE, 'Installed debugserver could not execute', diagnostic=result['stderr'][-1024:])
            return {'installed': True, 'path': destination, 'version': result['stdout'].strip()[:512], **installed,
                    'inspection_verified': False, **await self.check(device_id, bundle_id)}
