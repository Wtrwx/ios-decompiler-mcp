from __future__ import annotations

import importlib
import shutil
import uuid
from pathlib import Path
from typing import Any

from vesper.core.errors import Code, MCPError


def inspect_macho(path: Path, architecture: str | None = None, output: Path | None = None) -> dict[str, Any]:
    try:
        lief = importlib.import_module("lief")
    except ImportError as exc:
        raise MCPError(Code.UNAVAILABLE, "Install vesper[static] for Mach-O identity parsing") from exc
    try:
        fat = lief.MachO.parse(str(path))
        if fat is None:
            raise ValueError("not Mach-O")
        slices = []
        for binary in fat:
            cpu = str(binary.header.cpu_type).rsplit(".", 1)[-1].lower()
            subtype = binary.header.cpu_subtype & 0xFFFFFF
            arch = "arm64e" if cpu == "arm64" and subtype == 2 else cpu
            slices.append((arch, binary))
        selected = [item for item in slices if architecture is None or item[0] == architecture]
        if len(selected) != 1:
            raise MCPError(Code.INVALID_INPUT, "Select exactly one Mach-O architecture", available=[item[0] for item in slices])
        arch, binary = selected[0]
        identifier = str(uuid.UUID(bytes=bytes(binary.uuid.uuid))) if binary.has_uuid else None
        metadata = {"architecture": arch, "cpu_subtype": binary.header.cpu_subtype, "uuid": identifier, "image_base": binary.imagebase,
            "segments": [{"name": segment.name, "virtual_address": segment.virtual_address, "virtual_size": segment.virtual_size, "file_offset": segment.file_offset, "file_size": segment.file_size} for segment in binary.segments], "source": "LIEF Mach-O load commands"}
        if output is not None:
            if len(slices) == 1:
                shutil.copyfile(path, output)
            else:
                binary.write(str(output))
                if inspect_macho(output, arch) != metadata:
                    raise MCPError(Code.IDENTITY_MISMATCH, "Extracted Mach-O slice changed its UUID or segment layout")
        return metadata
    except MCPError:
        raise
    except Exception as exc:
        raise MCPError(Code.INVALID_INPUT, "Mach-O metadata could not be parsed", reason=type(exc).__name__) from exc


def correlate(metadata: dict[str, Any], runtime: dict[str, Any], ida_base: int) -> dict[str, Any]:
    static_uuid, runtime_uuid = metadata.get("uuid"), runtime.get("uuid")
    if not static_uuid or not runtime_uuid or static_uuid.lower() != runtime_uuid.lower():
        raise MCPError(Code.IDENTITY_MISMATCH, "Mach-O UUID evidence is missing or mismatched; no function match can be asserted", static_uuid=static_uuid, runtime_uuid=runtime_uuid)
    if metadata.get("architecture") != runtime.get("architecture"):
        raise MCPError(Code.IDENTITY_MISMATCH, "Mach-O CPU subtype/architecture differs from the runtime image")
    try:
        address = int(runtime["canonical_address"], 0)
        runtime_base = int(runtime["runtime_base"], 0)
        offset = address - runtime_base
    except (KeyError, ValueError, TypeError) as exc:
        raise MCPError(Code.INVALID_INPUT, "Runtime image must supply observed canonical address and module base") from exc
    if offset < 0 or offset >= runtime["size"]:
        raise MCPError(Code.IDENTITY_MISMATCH, "Runtime address is outside the observed module")
    static_address = metadata["image_base"] + offset
    segment = next((item for item in metadata["segments"] if item["virtual_address"] <= static_address < item["virtual_address"] + item["virtual_size"] and item["name"] != "__PAGEZERO"), None)
    if segment is None:
        raise MCPError(Code.IDENTITY_MISMATCH, "Runtime address does not map into a known static image segment")
    return {"static_virtual_address": hex(static_address), "ida_address": hex(ida_base + offset), "image_offset": hex(offset), "slide": hex(runtime_base - metadata["image_base"]), "uuid": static_uuid, "segment": segment["name"], "pac_stripped": runtime.get("pac_stripped", False), "evidence": "matching Mach-O UUID, architecture and segment bounds", "semantic_match_asserted": False}
