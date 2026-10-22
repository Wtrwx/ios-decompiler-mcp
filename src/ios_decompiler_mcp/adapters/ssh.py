from __future__ import annotations

import asyncio
import contextlib
import hashlib
import posixpath
import shlex
import stat
import uuid
from collections.abc import Awaitable, Callable
from functools import wraps
from pathlib import Path, PurePosixPath
from typing import Any, ParamSpec, TypeVar

import asyncssh

from ios_decompiler_mcp.config import Settings
from ios_decompiler_mcp.core.errors import Code, MCPError

P = ParamSpec("P")
T = TypeVar("T")


def transfer_errors(operation: Callable[P, Awaitable[T]]) -> Callable[P, Awaitable[T]]:
    @wraps(operation)
    async def invoke(*args: P.args, **kwargs: P.kwargs) -> T:
        try:
            return await operation(*args, **kwargs)
        except TimeoutError as exc:
            raise MCPError(Code.TIMEOUT, "SFTP operation timed out", retryable=True) from exc
        except (asyncssh.Error, OSError) as exc:
            raise MCPError(Code.SSH_ERROR, "SFTP operation failed", reason=type(exc).__name__, retryable=True) from exc
    return invoke


class SSHAdapter:
    """Only semantic operations select commands. No remote shell tool is registered."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.connections: dict[str, Any] = {}
        self.locks: dict[str, asyncio.Lock] = {}

    async def connect(self, device_id: str) -> Any:
        if device_id not in self.settings.devices:
            raise MCPError(Code.NOT_ALLOWED, "Device is not allowlisted")
        async with self.locks.setdefault(device_id, asyncio.Lock()):
            current = self.connections.get(device_id)
            if current is not None and not current.is_closed():
                return current
            config = self.settings.devices[device_id]
            try:
                connection = await asyncio.wait_for(asyncssh.connect(
                    config.host, config.port, username=config.username,
                    client_keys=[str(path.expanduser()) for path in config.client_keys],
                    known_hosts=str(config.known_hosts.expanduser()),
                    agent_path=None, password_auth=False, kbdint_auth=False,
                    config=None, connect_timeout=self.settings.operation_timeout,
                    keepalive_interval=15, keepalive_count_max=3,
                ), self.settings.operation_timeout)
            except TimeoutError as exc:
                raise MCPError(Code.TIMEOUT, "SSH connection timed out", retryable=True) from exc
            except (asyncssh.Error, OSError) as exc:
                raise MCPError(Code.SSH_ERROR, "SSH connection failed; check host key and public-key authentication", reason=type(exc).__name__) from exc
            self.connections[device_id] = connection
            return connection

    async def _run(self, device_id: str, command: str, *, timeout: float | None = None) -> dict[str, Any]:
        connection = await self.connect(device_id)
        prefix = self.settings.devices[device_id].jailbreak_prefix or "/var/jb"
        search_path = ":".join([prefix + "/usr/bin", prefix + "/usr/sbin", prefix + "/bin", prefix + "/sbin", "/usr/bin", "/usr/sbin", "/bin", "/sbin"])
        command = "PATH=" + shlex.quote(search_path) + "; export PATH; " + command
        try:
            # Stream to enforce the limit before an untrusted process exhausts host memory.
            async with asyncio.timeout(timeout or self.settings.operation_timeout):
                process = await connection.create_process(command, encoding="utf-8", errors="replace")
                async def read(stream: Any) -> str:
                    chunks, size = [], 0
                    while chunk := await stream.read(8192):
                        size += len(chunk)
                        if size > 262144:
                            process.terminate()
                            raise MCPError(Code.LIMIT_EXCEEDED, "SSH output exceeded 256 KiB")
                        chunks.append(chunk)
                    return "".join(chunks)
                try:
                    stdout, stderr = await asyncio.gather(read(process.stdout), read(process.stderr))
                    await process.wait_closed()
                    return {"stdout": stdout, "stderr": stderr, "exit_status": process.exit_status}
                except BaseException:
                    process.terminate()
                    process.close()
                    raise
        except TimeoutError as exc:
            raise MCPError(Code.TIMEOUT, "SSH operation timed out", retryable=True) from exc
        except (asyncssh.Error, OSError) as exc:
            self.connections.pop(device_id, None)
            raise MCPError(Code.SSH_ERROR, "SSH operation failed; reconnect before retrying mutations", reason=type(exc).__name__, retryable=True) from exc

    async def probe(self, device_id: str) -> dict[str, Any]:
        config = self.settings.devices[device_id]
        prefix = shlex.quote(config.jailbreak_prefix or "/var/jb")
        script = (
            "printf 'hardware_model='; uname -m; "
            "printf '\\ncpu_type='; sysctl -n hw.cputype 2>/dev/null || true; "
            "printf '\\ncpu_subtype='; sysctl -n hw.cpusubtype 2>/dev/null || true; "
            "printf '\\nios_version='; sw_vers -productVersion 2>/dev/null || "
            "plutil -extract ProductVersion raw -o - /System/Library/CoreServices/SystemVersion.plist; "
            f"if [ -d {prefix}/usr ]; then printf '\\nmode=rootless\\nprefix=%s\\n' {prefix}; "
            "else printf '\\nmode=rootful\\nprefix=\\n'; fi; "
            "printf 'dpkg='; command -v dpkg || true; "
            "printf 'frida_version='; "
            f"(command -v frida-server >/dev/null && frida-server --version) || {prefix}/usr/sbin/frida-server --version 2>/dev/null || true"
        )
        result = await self._run(device_id, script)
        if result["exit_status"] != 0:
            raise MCPError(Code.SSH_ERROR, "Device discovery failed", exit_status=result["exit_status"])
        data = dict(line.split("=", 1) for line in result["stdout"].splitlines() if "=" in line)
        # On physical iOS, uname -m reports a model such as iPhone11,8,
        # rather than an executable architecture. CPU subtype is recorded but
        # arm64e build selection still requires the target Mach-O's own subtype.
        cpu_type = data.get("cpu_type", "")
        architectures = {"16777228": "arm64", "12": "arm", "16777223": "x86_64", "7": "i386"}
        machine = data.get("hardware_model", "")
        data["architecture"] = architectures.get(cpu_type) or data.get("architecture") or (machine if machine in {"arm64", "arm64e", "x86_64", "i386"} else "unknown")
        if not data.get("architecture") or not data.get("ios_version"):
            raise MCPError(Code.UNAVAILABLE, "Device did not provide architecture and iOS version")
        return {"device_id": device_id, **data, "observed": True}

    @staticmethod
    def _remote_within(path: str, roots: list[str]) -> str:
        if not path.startswith("/") or ".." in PurePosixPath(path).parts or "\x00" in path:
            raise MCPError(Code.NOT_ALLOWED, "Device path must be absolute without traversal")
        normalized = posixpath.normpath(path)
        if not any(normalized == root.rstrip("/") or normalized.startswith(root.rstrip("/") + "/") for root in roots):
            raise MCPError(Code.NOT_ALLOWED, "Device path is outside configured transfer roots")
        return normalized

    @transfer_errors
    async def upload(self, device_id: str, local: Path, remote: str, *, expected_sha256: str | None = None) -> dict[str, Any]:
        config = self.settings.devices[device_id]
        remote = self._remote_within(remote, [config.staging_directory])
        if local.stat().st_size > self.settings.max_transfer_bytes:
            raise MCPError(Code.LIMIT_EXCEEDED, "Upload exceeds configured size limit")
        connection = await self.connect(device_id)
        async with asyncio.timeout(self.settings.operation_timeout):
            async with connection.start_sftp_client() as sftp:
                await sftp.makedirs(config.staging_directory, exist_ok=True)
                attrs = await sftp.lstat(config.staging_directory)
                if attrs.permissions is None or not stat.S_ISDIR(attrs.permissions):
                    raise MCPError(Code.NOT_ALLOWED, "Staging directory must be a real directory, not a symlink")
                owner = await sftp.stat(".")
                if attrs.uid is None or attrs.uid != owner.uid:
                    raise MCPError(Code.NOT_ALLOWED, "Staging directory must be owned by the SSH account")
                await sftp.chmod(config.staging_directory, 0o700)
                await sftp.makedirs(str(PurePosixPath(remote).parent), exist_ok=True)
                canonical_root = await sftp.realpath(config.staging_directory)
                canonical_parent = await sftp.realpath(str(PurePosixPath(remote).parent))
                self._remote_within(canonical_parent, [canonical_root])
                # Atomic replacement of a unique staged artifact; never follow a final symlink.
                temporary = remote + "." + uuid.uuid4().hex + ".uploading"
                try:
                    async with sftp.open(temporary, "xb", attrs=asyncssh.SFTPAttrs(permissions=0o600)) as output:
                        count = 0
                        digest = hashlib.sha256()
                        with local.open("rb") as source:
                            while chunk := source.read(65536):
                                count += len(chunk)
                                if count > self.settings.max_transfer_bytes:
                                    raise MCPError(Code.LIMIT_EXCEEDED, "Upload grew beyond size limit")
                                digest.update(chunk)
                                await output.write(chunk)
                    if expected_sha256 and digest.hexdigest() != expected_sha256:
                        raise MCPError(Code.IDENTITY_MISMATCH, "Upload source changed after operator approval")
                    await sftp.posix_rename(temporary, remote)
                finally:
                    with contextlib.suppress(asyncssh.SFTPError):
                        await sftp.remove(temporary)
        return {"remote_path": remote, "bytes": local.stat().st_size}

    @transfer_errors
    async def download(self, device_id: str, remote: str, local: Path) -> dict[str, Any]:
        config = self.settings.devices[device_id]
        remote = self._remote_within(remote, config.download_roots)
        connection = await self.connect(device_id)
        local.parent.mkdir(parents=True, exist_ok=True)
        async with asyncio.timeout(self.settings.operation_timeout):
            async with connection.start_sftp_client() as sftp:
                canonical = await sftp.realpath(remote)
                roots = [await sftp.realpath(root) for root in config.download_roots]
                self._remote_within(canonical, roots)
                attrs = await sftp.stat(canonical)
                if attrs.size is None or attrs.size > self.settings.max_transfer_bytes:
                    raise MCPError(Code.LIMIT_EXCEEDED, "Download exceeds configured size limit")
                temporary = local.with_name(local.name + "." + uuid.uuid4().hex + ".partial")
                try:
                    size = 0
                    async with sftp.open(canonical, "rb") as source:
                        with temporary.open("xb") as output:
                            while chunk := await source.read(65536):
                                size += len(chunk)
                                if size > self.settings.max_transfer_bytes:
                                    raise MCPError(Code.LIMIT_EXCEEDED, "Download grew beyond size limit")
                                output.write(chunk)
                    temporary.replace(local)
                finally:
                    temporary.unlink(missing_ok=True)
        return {"local_path": str(local), "bytes": size}

    async def package_status(self, device_id: str, package_id: str) -> dict[str, Any]:
        result = await self._run(device_id, shlex.join(["dpkg-query", "-W", "-f=${Status}\\n${Version}\\n${Architecture}\\n", package_id]))
        lines = result["stdout"].splitlines()
        return {"installed": result["exit_status"] == 0 and bool(lines) and lines[0] == "install ok installed", "version": lines[1] if len(lines) > 1 else None, "architecture": lines[2] if len(lines) > 2 else None}

    async def install(self, device_id: str, remote_package: str) -> dict[str, Any]:
        config = self.settings.devices[device_id]
        remote_package = self._remote_within(remote_package, [config.staging_directory])
        return await self._run(device_id, shlex.join(["dpkg", "--install", remote_package]), timeout=120)

    async def uninstall(self, device_id: str, package_id: str) -> dict[str, Any]:
        return await self._run(device_id, shlex.join(["dpkg", "--remove", package_id]), timeout=120)

    @transfer_errors
    async def file_sha256(self, device_id: str, remote_path: str) -> str:
        connection = await self.connect(device_id)
        digest, count = hashlib.sha256(), 0
        async with asyncio.timeout(self.settings.operation_timeout):
            async with connection.start_sftp_client() as sftp:
                async with sftp.open(remote_path, "rb") as source:
                    while chunk := await source.read(65536):
                        count += len(chunk)
                        if count > self.settings.max_transfer_bytes:
                            raise MCPError(Code.LIMIT_EXCEEDED, "Installed artifact exceeds size limit")
                        digest.update(chunk)
        return digest.hexdigest()

    @transfer_errors
    async def list_crashes(self, device_id: str, executable: str, since: float) -> list[dict[str, Any]]:
        connection = await self.connect(device_id)
        crashes = []
        readable = False
        async with asyncio.timeout(self.settings.operation_timeout):
            async with connection.start_sftp_client() as sftp:
                for root in self.settings.devices[device_id].crash_roots:
                    try:
                        async for entry in sftp.scandir(root):
                            if entry.filename.startswith(executable + "-") and entry.filename.endswith((".ips", ".crash")) and (entry.attrs.mtime or 0) >= since:
                                crashes.append({"name": entry.filename, "modified_at": entry.attrs.mtime})
                                if len(crashes) >= 100:
                                    return crashes
                        readable = True
                    except (asyncssh.SFTPNoSuchFile, asyncssh.SFTPPermissionDenied):
                        continue
        if not readable:
            raise MCPError(Code.UNAVAILABLE, "Crash directories are inaccessible; absence of crashes cannot be verified")
        return crashes

    async def close(self) -> None:
        for connection in self.connections.values():
            connection.close()
        await asyncio.gather(*(connection.wait_closed() for connection in self.connections.values()), return_exceptions=True)
        self.connections.clear()
