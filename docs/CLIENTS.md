# MCP client setup

Use absolute paths and a private config copied from `examples/vesper.toml`.
Install the project first with `uv sync --frozen --all-extras --no-editable`.
Client permission prompts do not grant vesper's own device-mutation approvals.
Run only one server process per state directory; use a different `state_dir` if
you need independent clients simultaneously.

## Codex

Add to your user or project Codex configuration, following
[official OpenAI MCP documentation](https://developers.openai.com/codex/mcp/):

```toml
[mcp_servers.vesper]
command = "/absolute/path/to/vesper/.venv/bin/vesper"
args = ["--config", "/absolute/path/to/vesper/vesper.local.toml"]
cwd = "/absolute/path/to/vesper"
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
    "vesper": {
      "command": "/absolute/path/to/vesper/.venv/bin/vesper",
      "args": ["--config", "/absolute/path/to/vesper/vesper.local.toml"]
    }
  }
}
```

The config's absolute `workspace` and `state_dir` remove dependence on the
client's working directory. Keep keys, database files, and local config private.
The server registers tool input/output schemas through MCP `tools/list` and
does not require an OpenAI or other model API key.

## Initial inspection

With the configured app already running, call `ui_capture(device_id, bundle_id,
mode="summary")` or explicit `"screenshot"`/`"both"`. It attaches only when needed.
Read the returned immutable cursor with `ui_snapshot`; new live observations omit
`snapshot_id`. No preliminary app/window enumeration is necessary.

The focused catalog loads 19 common tools. For an advanced primitive, call
`platform_tool(name="objc_get_ivars", action="schema")`, then execute through
`platform_tool(name="objc_get_ivars", arguments={...})`. Set top-level
`tool_profile="full"` to advertise all 70 tools directly.

Copy `skills/vesper-ios` into your agent's skill directory (for Codex,
`~/.codex/skills/vesper-ios`). Its conditional references cover decryption +
classdumpc/IDA, SSH tweak work, and debugging fallbacks. It keeps orchestration
out of the always-loaded MCP schemas. The skill can be selected automatically or
invoked as `$vesper-ios`.
