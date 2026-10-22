"""Exercise the optional adapter against a real local, operator-provided Mach-O."""
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from ios_decompiler_mcp.app import Application
from ios_decompiler_mcp.config import Settings


async def verify(args: argparse.Namespace) -> None:
    settings = Settings(ida_directory=args.ida_directory, ida_python=args.ida_python)
    app = Application(settings)
    try:
        result = await app.ida.open(args.path.resolve(), args.architecture)
        print(json.dumps(result, indent=2))
        functions = await app.ida.rpc(result["ida_session_id"], "list_functions", {"limit": 5})
        print(json.dumps(functions, indent=2))
        if functions["functions"]:
            address = functions["functions"][0]["address"]
            print(json.dumps(await app.ida.rpc(result["ida_session_id"], "get_function", {"address": address, "limit": 5}), indent=2))
            print(json.dumps(await app.ida.rpc(result["ida_session_id"], "xrefs", {"address": address, "limit": 5}), indent=2))
            try:
                print(json.dumps(await app.ida.rpc(result["ida_session_id"], "decompile", {"address": address}), indent=2))
            except Exception as optional:
                print(json.dumps({"optional_decompiler": "unavailable", "details": getattr(optional, "details", {})}, indent=2))
    except Exception as exc:
        print(json.dumps({"error": type(exc).__name__, "message": str(exc), "details": getattr(exc, "details", {})}, indent=2))
        raise SystemExit(1) from exc
    finally:
        await app.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path)
    parser.add_argument("--ida-directory", type=Path)
    parser.add_argument("--ida-python", type=Path)
    parser.add_argument("--architecture", default="arm64")
    asyncio.run(verify(parser.parse_args()))
