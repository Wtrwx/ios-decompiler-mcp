# MCP client setup

Use absolute paths and a private config copied from `examples/ios-decompiler-mcp.toml`.
Install the project first with `uv sync --frozen --all-extras --no-editable`.
Client permission prompts do not grant iOS Decompiler MCP's own device-mutation approvals.
Run only one server process per state directory; use a different `state_dir` if
you need independent clients simultaneously.

## Codex

Add to your user or project Codex configuration, following
[official OpenAI MCP documentation](https://developers.openai.com/codex/mcp/):

```toml
[mcp_servers.ios_decompiler]
command = "/absolute/path/to/ios-decompiler-mcp/.venv/bin/ios-decompiler-mcp"
args = ["--config", "/absolute/path/to/ios-decompiler-mcp/ios-decompiler-mcp.local.toml"]
cwd = "/absolute/path/to/ios-decompiler-mcp"
startup_timeout_sec = 20
tool_timeout_sec = 240
```

Background build/workflow jobs return quickly. Retrieve their status through
`job_status` instead of holding a client tool request open for an entire build.

## Claude Code and Cursor

Use this stdio entry in your client's MCP JSON configuration
([Claude Code](https://code.claude.com/docs/en/mcp): `.mcp.json`;
[Cursor](https://cursor.com/docs/context/mcp): `.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "ios_decompiler": {
      "command": "/absolute/path/to/ios-decompiler-mcp/.venv/bin/ios-decompiler-mcp",
      "args": ["--config", "/absolute/path/to/ios-decompiler-mcp/ios-decompiler-mcp.local.toml"]
    }
  }
}
```

The config's absolute `workspace` and `state_dir` remove dependence on the
client's working directory. Keep keys, database files, and local config private.
The server registers tool input/output schemas through MCP `tools/list` and
does not require an OpenAI or other model API key.

## Initial inspection

Call `server_status`, `device_list`, `frida_list_devices`, `device_connect`, then
`device_list_apps`. Configure the observed USB device ID rather than choosing
an arbitrary USB device. With the selected app already running, call
`frida_attach` with its bundle ID and observed PID. Use that returned session ID
for UI, runtime and trace tools. Text is omitted by default; request it only for
the relevant app inspection. Detach when done to release hooks and retained IDs.
