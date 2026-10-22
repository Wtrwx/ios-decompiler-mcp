"""Isolated official idalib worker. All SDK calls run on its initializing thread.

Only the standard library is imported until the configured IDA installation loads.
Native SDK output goes to stderr; stdout is a bounded JSON-line protocol.
"""
from __future__ import annotations

import argparse
import contextlib
import itertools
import json
import os
import sys
from pathlib import Path
from typing import Any


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ida-directory", type=Path, required=True)
    parser.add_argument("--database", type=Path, required=True)
    args = parser.parse_args()
    protocol = os.fdopen(os.dup(sys.stdout.fileno()), "w", buffering=1)
    os.dup2(sys.stderr.fileno(), sys.stdout.fileno())

    def reply(value: dict[str, Any]) -> None:
        protocol.write(json.dumps(value) + "\n")

    opened = False
    try:
        root = args.ida_directory.resolve()
        os.environ["IDADIR"] = str(root)
        # IDA 9.1's package otherwise creates this user-global file during import.
        # Activation is an explicit operator setup step, never performed here.
        config = Path.home() / ".idapro" / "ida-config.json"
        if not config.is_file():
            raise RuntimeError("Activate idalib using your licensed installation's py-activate-idalib.py before starting this adapter")
        sdk_path = root / "idalib/python"
        if not (sdk_path / "idapro").is_dir():
            raise RuntimeError("Configured IDA directory has no official idapro package (requires IDA Pro 9+)")
        sys.path.insert(0, str(sdk_path))
        import idapro
        idapro.enable_console_messages(True)
        if idapro.open_database(str(args.database), True) != 0:
            raise RuntimeError("IDA could not open the database; check licensing and interpreter compatibility")
        opened = True
        import ida_auto
        import ida_funcs
        import ida_ida
        import ida_idaapi
        import ida_lines
        import ida_nalt
        import ida_name
        import idautils
        ida_auto.auto_wait()
        digest = ida_nalt.retrieve_input_file_sha256()
        metadata = {"image_base": ida_nalt.get_imagebase(), "processor": ida_ida.inf_get_procname(), "is_64bit": ida_ida.inf_is_64bit(), "input_sha256": bytes(digest).hex() if digest else None, "ida_version": list(idapro.get_library_version() or [])}
        reply({"ready": True, "metadata": metadata})

        def address(value: str) -> int:
            try:
                return int(value, 0)
            except ValueError:
                result = ida_name.get_name_ea(ida_idaapi.BADADDR, value)
                if result == ida_idaapi.BADADDR:
                    raise ValueError("Symbol is not present in the database") from None
                return result

        def function(ea: int) -> dict[str, Any]:
            item = ida_funcs.get_func(ea)
            if item is None:
                raise ValueError("Address is not within an analyzed function")
            return {"address": hex(item.start_ea), "end": hex(item.end_ea), "name": ida_funcs.get_func_name(item.start_ea), "size": item.end_ea - item.start_ea, "analysis": "IDA static analysis"}

        def execute(operation: str, values: dict[str, Any]) -> dict[str, Any]:
            limit = min(max(int(values.get("limit", 100)), 1), 500)
            offset = min(max(int(values.get("offset", 0)), 0), 1000000)
            if operation == "metadata":
                return metadata
            if operation == "list_functions":
                items = list(itertools.islice(idautils.Functions(), offset, offset + limit + 1))
                return {"functions": [function(ea) for ea in items[:limit]], "next_offset": offset + limit if len(items) > limit else None}
            if operation == "get_function":
                ea = address(values["address"])
                result = function(ea)
                lines = []
                for item in itertools.islice(idautils.FuncItems(int(result["address"], 0)), offset, offset + limit + 1):
                    line = ida_lines.generate_disasm_line(item, 0) or ""
                    lines.append({"address": hex(item), "text": ida_lines.tag_remove(line)})
                return {**result, "disassembly": lines[:limit], "next_offset": offset + limit if len(lines) > limit else None}
            if operation == "decompile":
                import ida_hexrays
                if not ida_hexrays.init_hexrays_plugin():
                    raise RuntimeError("Hex-Rays decompiler is not available for this processor/license")
                code = ida_hexrays.decompile(address(values["address"]))
                if code is None:
                    raise ValueError("Hex-Rays could not decompile this function")
                text = str(code)
                start = min(max(int(values.get("text_offset", 0)), 0), len(text))
                return {"pseudocode": text[start:start + 32768], "next_text_offset": start + 32768 if start + 32768 < len(text) else None, "analysis": "Hex-Rays inferred pseudocode, not source code"}
            if operation == "xrefs":
                ea = address(values["address"])
                generator = idautils.XrefsFrom(ea, 0) if values.get("direction") == "from" else idautils.XrefsTo(ea, 0)
                refs = list(itertools.islice(generator, offset, offset + limit + 1))
                return {"xrefs": [{"from": hex(ref.frm), "to": hex(ref.to), "type": ref.type, "is_code": bool(ref.iscode)} for ref in refs[:limit]], "next_offset": offset + limit if len(refs) > limit else None}
            if operation == "search_symbols":
                query = values.get("query", "").lower()
                matches = ((ea, name) for ea, name in idautils.Names() if query in name.lower())
                items = list(itertools.islice(matches, offset, offset + limit + 1))
                return {"symbols": [{"address": hex(ea), "name": name, "objc_reference": "objc" in name.lower() or "selref" in name.lower()} for ea, name in items[:limit]], "next_offset": offset + limit if len(items) > limit else None}
            raise ValueError("Unknown read-only IDA operation")

        for line in sys.stdin:
            if len(line) > 65536:
                raise ValueError("Worker request exceeds limit")
            request: dict[str, Any] = {}
            try:
                request = json.loads(line)
                if request["operation"] == "close":
                    reply({"id": request["id"], "result": {"closed": True}})
                    break
                reply({"id": request["id"], "result": execute(request["operation"], request.get("arguments", {}))})
            except Exception as exc:
                reply({"id": request.get("id"), "error": {"message": str(exc)[:1000], "reason": type(exc).__name__}})
    except Exception as exc:
        reply({"ready": False, "error": {"message": str(exc)[:1000], "reason": type(exc).__name__}})
    finally:
        if opened:
            with contextlib.suppress(Exception):
                idapro.close_database(True)
        protocol.close()


if __name__ == "__main__":
    main()
