from __future__ import annotations

import argparse
import asyncio
import base64
import json
import logging
import tomllib
from pathlib import Path
from typing import Any

from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from pydantic import ValidationError

from flex_mcp import __version__
from flex_mcp.app import Application
from flex_mcp.config import Settings
from flex_mcp.core.errors import FlexError
from flex_mcp.core.evidence import Result
from flex_mcp.tools import device, dynamic, runtime, static, tweak, ui
from flex_mcp.tools.models import Empty, JobRequest
from flex_mcp.workflows import develop_tweak


def create_server(app: Application) -> Server[Any, Any]:
    server: Server[Any, Any] = Server("ios-decompiler-mcp", version=__version__, instructions="Authorized operator-controlled devices only. Select an allowlisted application. Device mutations require a locally granted approval. Compilation alone never proves deployment success.")
    device.register(app)
    dynamic.register(app)
    runtime.register(app)
    ui.register(app)
    tweak.register(app)
    develop_tweak.register(app)
    static.register(app)

    async def status(_: Empty) -> dict[str, Any]:
        recovery = [{"deployment_id": item["deployment_id"], "phase": item["phase"], "device_id": item["device_id"], "package_id": item["package_id"]} for item in app.registry.list("deployment") if item.get("phase") in {"interrupted", "rollback_failed", "uninstall_failed"}]
        return {"version": __version__, "device_count": len(app.settings.devices), "sessions": [session.metadata() | {"active": session.active} for session in app.frida.sessions.values()], "inspection_default": "read_only", "approval_grant": "local operator CLI only", "recovery_required": recovery}

    async def job_status(request: JobRequest) -> dict[str, Any]:
        return app.registry.get(request.job_id, "job")

    async def job_cancel(request: JobRequest) -> dict[str, Any]:
        return await app.jobs.cancel(request.job_id)

    app.tools.add("server_status", Empty, status, "Inspect server configuration and process-session lifecycle without touching a device.")
    app.tools.add("job_status", JobRequest, job_status, "Retrieve a long-running job result.")
    app.tools.add("job_cancel", JobRequest, job_cancel, "Cancel a job and clean up its active operation.", read_only=False)

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return [types.Tool(name=tool.name, description=tool.description, inputSchema=tool.model.model_json_schema(), outputSchema=Result.model_json_schema(), annotations=types.ToolAnnotations(readOnlyHint=tool.read_only, destructiveHint=not tool.read_only, openWorldHint=False)) for tool in app.tools.tools.values()]

    @server.call_tool(validate_input=False)
    async def call_tool(name: str, arguments: dict[str, Any]) -> types.CallToolResult:
        result = await app.tools.invoke(name, arguments)
        structured = result.model_dump(mode="json")
        content: list[Any] = [types.TextContent(type="text", text=json.dumps(structured))]
        if name == "ui_screenshot" and result.ok and result.data:
            path = app.permissions.local_path(Path(result.data["local_path"]), must_exist=True)
            content.append(types.ImageContent(type="image", mimeType="image/png", data=base64.b64encode(path.read_bytes()).decode("ascii")))
        return types.CallToolResult(content=content, structuredContent=structured, isError=not result.ok)

    return server


async def run(settings: Settings) -> None:
    app = Application(settings)
    try:
        server = create_server(app)
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())
    finally:
        await app.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="iOS Decompiler MCP MCP stdio server")
    parser.add_argument("--config", type=Path)
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args()
    logging.basicConfig(level=logging.WARNING)  # stderr only; stdout belongs to MCP.
    try:
        asyncio.run(run(Settings.load(args.config)))
    except KeyboardInterrupt:
        pass
    except (ValidationError, tomllib.TOMLDecodeError, OSError) as exc:
        parser.error(f"Cannot start with this configuration ({type(exc).__name__}); check settings, paths and permissions. Input values are omitted.")
    except FlexError as exc:
        parser.exit(1, f"{exc.code}: {exc.message}\n")


if __name__ == "__main__":
    main()
