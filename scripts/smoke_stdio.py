"""Verify an installed wheel through stdio, without importing project source."""
from __future__ import annotations

import asyncio
import os
import sys
from importlib.metadata import distribution
from importlib.resources import files
from pathlib import Path
from tempfile import TemporaryDirectory

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def smoke() -> None:
    package = distribution("ios-decompiler-mcp")
    commands = {entry.name for entry in package.entry_points if entry.group == "console_scripts"}
    assert commands == {"ios-decompiler-mcp", "ios-decompiler-mcp-approve"}
    assert files("ios_decompiler_mcp").joinpath("assets/agent.js").is_file()
    with TemporaryDirectory() as directory:
        config = Path(directory) / "config.toml"
        config.write_text(f'workspace = "{directory}"\nstate_dir = "{directory}/state"\n')
        environment = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
        command = Path(sys.executable).with_name("ios-decompiler-mcp")
        parameters = StdioServerParameters(command=str(command), args=["--config", str(config)], cwd=directory, env=environment)
        async with stdio_client(parameters) as (read, write):
            async with ClientSession(read, write) as client:
                info = await client.initialize()
                assert info.serverInfo.name == "ios-decompiler-mcp"
                tools = (await client.list_tools()).tools
                assert len(tools) >= 60
                result = await client.call_tool("server_status", {})
                assert result.structuredContent and result.structuredContent["ok"]
                print(f"Installed-wheel MCP smoke passed: {len(tools)} tools")


if __name__ == "__main__":
    asyncio.run(smoke())
