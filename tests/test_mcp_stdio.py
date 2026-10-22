from __future__ import annotations

import base64
import os
import struct
import subprocess
import sys
import zlib
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.shared.memory import create_connected_server_and_client_session

from flex_mcp.app import Application
from flex_mcp.server import create_server


@pytest.mark.asyncio
async def test_real_stdio_discovery_and_invocation(tmp_path: Path):
    config = tmp_path / "server.toml"
    config.write_text(f'workspace = "{tmp_path}"\nstate_dir = "{tmp_path / "state"}"\n')
    parameters = StdioServerParameters(command=sys.executable, args=["-m", "flex_mcp.server", "--config", str(config)], env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")})
    async with stdio_client(parameters) as (read, write):
        async with ClientSession(read, write) as client:
            info = await client.initialize()
            assert info.serverInfo.name == "ios-decompiler-mcp"
            tools = (await client.list_tools()).tools
            names = {tool.name for tool in tools}
            assert {"server_status", "device_connect", "frida_attach", "objc_search_classes", "ui_snapshot"} <= names
            status = await client.call_tool("server_status", {})
            assert not status.isError
            assert status.structuredContent["ok"]
            denied = await client.call_tool("device_connect", {"device_id": "not-configured"})
            assert denied.isError
            assert denied.structuredContent["error"]["code"] == "NOT_ALLOWED"


async def test_native_screenshot_image_uses_mcp_content_block(settings):
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
    png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(b"\0\0")) + chunk(b"IEND", b"")
    app = Application(settings)
    server = create_server(app)
    app.frida.rpc = AsyncMock(return_value={"base64": base64.b64encode(png).decode(), "window_id": "process_test:object_1"})
    try:
        async with create_connected_server_and_client_session(server) as client:
            result = await client.call_tool("ui_screenshot", {"device_id": "test", "session_id": "process_test"})
            assert not result.isError and result.structuredContent["ok"]
            images = [item for item in result.content if item.type == "image"]
            assert len(images) == 1 and images[0].mimeType == "image/png"
            assert base64.b64decode(images[0].data) == png
    finally:
        await app.close()


def test_startup_config_errors_do_not_echo_secret_values(tmp_path):
    config = tmp_path / "bad.toml"
    config.write_text('[devices.test]\nhost="localhost"\npassword="never-echo-this-secret"\n')
    result = subprocess.run([sys.executable, "-m", "flex_mcp.server", "--config", str(config)], env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")}, capture_output=True, text=True, timeout=10)
    assert result.returncode == 2
    assert "never-echo-this-secret" not in result.stderr and "ValidationError" in result.stderr
