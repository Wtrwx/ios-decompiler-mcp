from __future__ import annotations

import argparse
import asyncio
import base64
import json
import logging
import time
import tomllib
from pathlib import Path
from typing import Any

from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from pydantic import ValidationError

from vesper import __version__
from vesper.app import Application
from vesper.config import Settings
from vesper.core.errors import MCPError
from vesper.core.evidence import Result
from vesper.tools import (
    automation,
    debug,
    decrypt,
    device,
    dump,
    dynamic,
    instances,
    platform,
    runtime,
    static,
    tweak,
    ui,
)
from vesper.tools.models import Empty, JobRequest
from vesper.workflows import develop_tweak


def create_server(app: Application) -> Server[Any, Any]:
    app.start_maintenance()
    server: Server[Any, Any] = Server("Vesper iOS", version=__version__, instructions="iOS reverse engineering platform. Use ui_capture for one-call live UI inspection; ui_automate batches app actions. Prefer bounded fields/pages. Use the vesper-ios skill for backend selection and tweak regression workflows. Compilation alone never proves deployment success.")
    device.register(app)
    dynamic.register(app)
    runtime.register(app)
    dump.register(app)
    instances.register(app)
    ui.register(app)
    automation.register(app)
    debug.register(app)
    decrypt.register(app)
    tweak.register(app)
    develop_tweak.register(app)
    static.register(app)

    async def status(_: Empty) -> dict[str, Any]:
        recovery = [{"deployment_id": item["deployment_id"], "phase": item["phase"], "device_id": item["device_id"], "package_id": item["package_id"]} for item in app.registry.list("deployment") if item.get("phase") in {"interrupted", "rollback_failed", "uninstall_failed"}]
        return {"name": "vesper", "version": __version__, "device_count": len(app.settings.devices), "tool_count": len(app.tools.tools), "sessions": [session.metadata() | {"active": session.active} for session in app.frida.sessions.values()], "inspection_default": "read_only", "approval_grant": "local operator CLI only", "recovery_required": recovery}

    async def job_status(request: JobRequest) -> dict[str, Any]:
        return app.registry.get(request.job_id, "job")

    async def job_cancel(request: JobRequest) -> dict[str, Any]:
        return await app.jobs.cancel(request.job_id)

    app.tools.add("server_status", Empty, status, "Inspect server configuration and process-session lifecycle without touching a device.")
    app.tools.add("job_status", JobRequest, job_status, "Retrieve a long-running job result.")
    app.tools.add("job_cancel", JobRequest, job_cancel, "Cancel a job and clean up its active operation.", read_only=False)
    platform.register(app)

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return [types.Tool(name=tool.name, description=tool.description, inputSchema=tool.model.model_json_schema(), outputSchema=Result.model_json_schema(), annotations=types.ToolAnnotations(readOnlyHint=tool.read_only, destructiveHint=not tool.read_only, openWorldHint=False)) for tool in app.tools.tools.values()
                if app.settings.tool_profile == 'full' or tool.name in platform.FOCUSED_TOOLS]

    @server.call_tool(validate_input=False)
    async def call_tool(name: str, arguments: dict[str, Any]) -> types.CallToolResult:
        result = await app.tools.invoke(name, arguments)
        images: list[Any] = []
        image_tool = arguments.get('name') if name == 'platform_tool' and arguments.get('action', 'call') == 'call' else name
        if image_tool in {"ui_screenshot", "ui_capture", "ui_automate"} and result.ok and result.data:
            screenshot = result.data if image_tool == "ui_screenshot" else result.data.get("screenshot")
            if screenshot:
                started = time.perf_counter()
                path = app.permissions.local_path(Path(screenshot["local_path"]), must_exist=True)
                images.append(types.ImageContent(type="image", mimeType="image/png", data=base64.b64encode(path.read_bytes()).decode("ascii")))
                screenshot.setdefault("timings_ms", {})["image_content"] = round((time.perf_counter() - started) * 1000, 3)
        structured = result.model_dump(mode="json")
        text = json.dumps(structured) if app.settings.legacy_text_json else (
            f"{name}: ok. Structured result attached." if result.ok else
            f"{name}: {result.error.code}: {result.error.message}" if result.error else f"{name}: failed")
        content: list[Any] = [types.TextContent(type="text", text=text), *images]
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
    parser = argparse.ArgumentParser(description="vesper — iOS reverse engineering platform (MCP stdio)")
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
    except MCPError as exc:
        parser.exit(1, f"{exc.code}: {exc.message}\n")


if __name__ == "__main__":
    main()
