from __future__ import annotations

import asyncio
import hashlib
import os
import shutil
import time
from collections import OrderedDict
from pathlib import Path
from typing import TYPE_CHECKING, Any

from vesper.core.errors import Code, MCPError

if TYPE_CHECKING:
    from vesper.app import Application


class ClassDumpAdapter:
    """Bounded static header artifacts; never silently substitutes class-dump."""

    def __init__(self, app: Application):
        self.app = app
        self.cache: OrderedDict[str, tuple[float, Path, int]] = OrderedDict()
        self.lock = asyncio.Lock()

    def executable(self) -> str | None:
        configured = self.app.settings.classdumpc
        path = str(configured) if configured else shutil.which('classdumpc')
        return path if path and Path(path).is_file() and os.access(path, os.X_OK) else None

    def expire(self) -> None:
        now = time.monotonic()
        for key, (expires, path, _) in list(self.cache.items()):
            if expires <= now:
                path.unlink(missing_ok=True)
                del self.cache[key]

    def close(self) -> None:
        for _, path, _ in self.cache.values():
            path.unlink(missing_ok=True)
        self.cache.clear()

    async def dump(self, path: Path, class_filter: str | None, arch: str | None, preview_chars: int) -> dict[str, Any]:
        executable = self.executable()
        if not executable:
            raise MCPError(Code.UNAVAILABLE, 'classdumpc is missing', component='classdumpc',
                install_hint='Install classdumpc on the host or set classdumpc to its absolute executable path. Use objc_dump(backend=runtime) for loaded classes.')
        source = self.app.permissions.local_path(path, must_exist=True)
        if source.stat().st_size > self.app.settings.max_decrypt_bytes:
            raise MCPError(Code.LIMIT_EXCEEDED, 'Binary exceeds max_decrypt_bytes')
        with source.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        key = hashlib.sha256(repr((digest, executable, Path(executable).stat().st_mtime_ns, class_filter, arch)).encode()).hexdigest()
        async with self.lock:
            self.expire()
            cached = self.cache.get(key)
            reused = bool(cached and cached[1].is_file())
            if not reused:
                destination = self.app.settings.state_dir / 'headers' / (key + '.h')
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                arguments = [executable, '-t', '-s', '-S']
                if class_filter:
                    arguments += ['-C', class_filter]
                if arch:
                    arguments += ['--arch', arch]
                arguments.append(str(source))
                process: Any = None
                readers: list[asyncio.Task[int]] = []
                error = bytearray()

                async def copy(stream: Any, output: Any = None) -> int:
                    total = 0
                    while chunk := await stream.read(16384):
                        total += len(chunk)
                        if total > (8 * 1024 * 1024 if output else 65536):
                            raise MCPError(Code.LIMIT_EXCEEDED, 'classdumpc output exceeded its bound; select a class_name or class_filter')
                        if output:
                            output.write(chunk)
                        else:
                            error.extend(chunk)
                    return total

                succeeded = False
                try:
                    with destination.open('wb') as output:
                        destination.chmod(0o600)
                        process = await asyncio.create_subprocess_exec(*arguments, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                        async with asyncio.timeout(self.app.settings.operation_timeout):
                            readers = [asyncio.create_task(copy(process.stdout, output)), asyncio.create_task(copy(process.stderr))]
                            try:
                                await asyncio.gather(*readers)
                            finally:
                                for reader in readers:
                                    reader.cancel()
                                await asyncio.gather(*readers, return_exceptions=True)
                            await process.wait()
                    if process.returncode:
                        raise MCPError(Code.UNAVAILABLE, 'classdumpc failed; encrypted or stripped metadata may require the live runtime backend',
                            exit_status=process.returncode, diagnostic=error.decode('utf-8', errors='replace')[-2048:])
                    size = destination.stat().st_size
                    while self.cache and (len(self.cache) >= 4 or sum(item[2] for item in self.cache.values()) + size > 16 * 1024 * 1024):
                        _, (_, old, _) = self.cache.popitem(last=False)
                        old.unlink(missing_ok=True)
                    self.cache[key] = (time.monotonic() + 300, destination, size)
                    succeeded = True
                except TimeoutError as exc:
                    raise MCPError(Code.TIMEOUT, 'classdumpc timed out') from exc
                finally:
                    if process is not None and process.returncode is None:
                        process.kill()
                        await process.wait()
                    if not succeeded:
                        destination.unlink(missing_ok=True)
            else:
                assert cached is not None
                destination, size = cached[1], cached[2]
                self.cache.move_to_end(key)
            result: dict[str, Any] = {'backend': 'classdumpc', 'source_sha256': digest, 'local_path': str(destination),
                'bytes': size, 'reused': reused, 'retention_seconds': 300, 'source': 'static_objc_metadata'}
            if preview_chars:
                with destination.open(encoding='utf-8', errors='replace') as text_stream:
                    result['preview'] = text_stream.read(preview_chars)
                result['preview_truncated'] = size > len(result['preview'].encode())
            return result
