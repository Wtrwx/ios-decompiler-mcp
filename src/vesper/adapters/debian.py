from __future__ import annotations

import io
import lzma
import plistlib
import tarfile
import zlib
from pathlib import Path, PurePosixPath
from typing import Any

from vesper.core.errors import Code, MCPError


def _read_members(path: Path, limit: int) -> dict[str, bytes]:
    """Read deb(5)'s common ar format, including optional filename slashes."""
    if path.stat().st_size > limit:
        raise MCPError(Code.LIMIT_EXCEEDED, "Package exceeds the upload limit")
    with path.open("rb") as package:
        content = package.read(limit + 1)
    if len(content) > limit:
        raise MCPError(Code.LIMIT_EXCEEDED, "Package exceeds the upload limit")
    if not content.startswith(b"!<arch>\n"):
        raise MCPError(Code.INVALID_INPUT, "Invalid Debian archive signature")

    members: dict[str, bytes] = {}
    offset = 8
    while offset < len(content):
        header = content[offset:offset + 60]
        if len(header) != 60 or header[58:] != b"`\n":
            raise MCPError(Code.INVALID_INPUT, "Invalid or truncated Debian archive header")
        # Debian packages forbid GNU/BSD long-name extensions. A trailing slash
        # is optional and must not become part of the member's logical name.
        name = header[:16].rstrip(b" ").removesuffix(b"/")
        if not name or len(name) > 15 or b"/" in name or name in {b".", b".."} or any(byte < 33 or byte > 126 for byte in name):
            raise MCPError(Code.INVALID_INPUT, "Unsupported Debian archive member name")
        key = name.decode("ascii")
        if key in members:
            raise MCPError(Code.INVALID_INPUT, "Duplicate Debian archive member")
        if len(members) >= 512:
            raise MCPError(Code.LIMIT_EXCEEDED, "Too many Debian archive members")
        size_field = header[48:58].strip(b" ")
        if not size_field.isdigit():
            raise MCPError(Code.INVALID_INPUT, "Invalid Debian archive member size")
        size = int(size_field)
        if size > limit:
            raise MCPError(Code.LIMIT_EXCEEDED, "Debian archive member exceeds the size limit")
        start, end = offset + 60, offset + 60 + size
        if end > len(content) or (size % 2 and content[end:end + 1] != b"\n"):
            raise MCPError(Code.INVALID_INPUT, "Truncated Debian archive member or invalid padding")
        members[key] = content[start:end]
        offset = end + size % 2
    return members


def inspect_package(path: Path, expected: dict[str, Any], limit: int) -> dict[str, Any]:
    """Inspect archives without extracting or executing package-maintainer scripts."""
    members = _read_members(path, limit)
    if members.get("debian-binary") != b"2.0\n":
        raise MCPError(Code.INVALID_INPUT, "Unsupported Debian package format")
    selected: dict[str, str] = {}
    for kind in ("control", "data"):
        matches = [name for name in members if name.startswith(kind + ".tar")]
        if len(matches) != 1:
            raise MCPError(Code.INVALID_INPUT, "Package requires exactly one control and data archive")
        selected[kind] = matches[0]

    def entries(kind: str) -> dict[str, bytes]:
        packed = members[selected[kind]]
        result: dict[str, bytes] = {}
        total = 0
        try:
            # Decompress before tarfile parses PAX metadata, with an explicit cap.
            # Checking only TarInfo.size is too late for a compressed metadata bomb.
            member_name = selected[kind]
            if member_name.endswith(".gz"):
                gzip_decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
                packed = gzip_decoder.decompress(packed, limit * 4 + 1)
                complete = gzip_decoder.eof
            elif member_name.endswith((".xz", ".lzma")):
                decoder = lzma.LZMADecompressor(memlimit=max(limit * 4, 32 * 1024 * 1024))
                packed = decoder.decompress(packed, max_length=limit * 4 + 1)
                complete = decoder.eof
            elif member_name.endswith(".tar"):
                complete = True
            else:
                raise MCPError(Code.INVALID_INPUT, "Use gzip/xz/lzma or uncompressed Debian archives")
            if not complete or len(packed) > limit * 4:
                raise MCPError(Code.LIMIT_EXCEEDED, "Package decompression exceeded the size limit or is incomplete")
            with tarfile.open(fileobj=io.BytesIO(packed), mode="r:") as archive:
                for index, member in enumerate(archive):
                    if index > 512:
                        raise MCPError(Code.LIMIT_EXCEEDED, "Too many package entries")
                    name = str(PurePosixPath(member.name))
                    if name.startswith("/") or ".." in PurePosixPath(name).parts or member.issym() or member.islnk():
                        raise MCPError(Code.NOT_ALLOWED, "Package contains unsafe paths or links")
                    if member.isdir():
                        continue
                    if not member.isfile():
                        raise MCPError(Code.NOT_ALLOWED, "Package contains unsupported device entries")
                    total += member.size
                    if total > limit * 4 or member.size > limit:
                        raise MCPError(Code.LIMIT_EXCEEDED, "Expanded package exceeds the size limit")
                    source = archive.extractfile(member)
                    if source is None or name in result:
                        raise MCPError(Code.INVALID_INPUT, "Invalid or duplicate package entry")
                    result[name] = source.read(limit + 1)
            return result
        except (tarfile.TarError, lzma.LZMAError, zlib.error) as exc:
            raise MCPError(Code.INVALID_INPUT, "Unsupported or malformed package compression; use gzip/xz packaging") from exc

    control, payload = entries("control"), entries("data")
    if set(control) - {"control", "md5sums"}:
        raise MCPError(Code.NOT_ALLOWED, "Default deployment does not permit package-maintainer scripts or extra control records")
    fields = {}
    for line in control.get("control", b"").decode(errors="replace").splitlines():
        if ":" in line and not line.startswith(" "):
            key, value = line.split(":", 1)
            fields[key] = value.strip()
    architecture = "iphoneos-arm64" if expected["rootless"] else "iphoneos-arm"
    if fields.get("Package") != expected["package_id"] or fields.get("Version") != expected["version"] or fields.get("Architecture") != architecture:
        raise MCPError(Code.IDENTITY_MISMATCH, "Debian package metadata differs from the project specification")
    prefix = "var/jb/" if expected["rootless"] else ""
    base = prefix + "Library/MobileSubstrate/DynamicLibraries/" + expected["name"]
    allowed = {base + ".dylib", base + ".plist"}
    if set(payload) != allowed:
        raise MCPError(Code.NOT_ALLOWED, "Default deployment permits only this tweak's dylib and application filter", actual_files=sorted(payload), expected_files=sorted(allowed))
    try:
        injection = plistlib.loads(payload[base + ".plist"])
    except Exception as exc:
        raise MCPError(Code.INVALID_INPUT, "Package injection plist is invalid") from exc
    if injection != {"Filter": {"Bundles": [expected["bundle_id"]]}}:
        raise MCPError(Code.NOT_ALLOWED, "Package must inject into exactly the explicitly selected application")
    import hashlib
    return {"package_id": fields["Package"], "version": fields["Version"], "architecture": architecture,
        "files": sorted(payload), "dylib_path": "/" + base + ".dylib", "dylib_sha256": hashlib.sha256(payload[base + ".dylib"]).hexdigest()}
