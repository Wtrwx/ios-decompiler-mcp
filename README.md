# iOS Decompiler MCP

[English](README.md) | [简体中文](README.zh-CN.md)

An MCP server for iOS runtime inspection, reverse engineering, and Theos/Logos
tweak development on operator-controlled, jailbroken iPhones.

iOS Decompiler MCP connects an MCP client to SSH, Frida, and an optional licensed IDA
installation. Inspect UIKit views, explore Objective-C metadata, trace method
calls, and build app-scoped tweaks through structured tools. Device changes use
a separate local approval flow.

## Contents

- [Features](#features)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Demos](#demos)
- [Project structure](#project-structure)
- [Development](#development)
- [Security and scope](#security-and-scope)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)

## Features

| Area | Capabilities | Example tools |
| --- | --- | --- |
| Devices | SSH/SFTP, device discovery, app and process enumeration | `device_connect`, `device_info`, `device_list_apps` |
| UIKit | Windows and scenes, view trees, hit testing, constraints, responder chains, screenshots | `ui_snapshot`, `ui_inspect_view`, `ui_screenshot` |
| Objective-C | Classes, methods, properties, ivars, IMPs, object metadata, generated headers | `objc_dump_class`, `objc_get_methods`, `objc_generate_header` |
| Dynamic analysis | Persistent Frida sessions, observation hooks, bounded events and call stacks | `frida_attach`, `frida_trace_method`, `frida_get_events` |
| Static analysis | Optional headless IDA, disassembly, Hex-Rays pseudocode, cross-references, runtime address correlation | `ida_open_binary`, `ida_decompile`, `ida_resolve_runtime_address` |
| Tweak development | Editable Logos projects, ABI validation, Theos builds, approved deployment, verification and rollback | `tweak_create_project`, `tweak_build`, `tweak_deploy` |
| Workflows | Button-title tweak workflow, persistent reports, background jobs and cancellation | `develop_tweak`, `job_status`, `job_cancel` |

See the [tool reference](docs/TOOLS.md) for the complete catalog and required fields.

## Requirements

| Component | Requirement |
| --- | --- |
| Host | macOS or Linux, Python 3.11+, [uv](https://docs.astral.sh/uv/) |
| Device | An operator-controlled jailbroken iPhone with SSH public-key authentication |
| Frida | Frida 17.x, at least 17.5; the host client and device server must match exactly |
| Tweak builds | [Theos](https://theos.dev/), Logos, `make`, a compatible iOS SDK, compiler/linker and signing tools |
| Tweak deployment | A compatible injection substrate and an SSH account permitted to install packages with `dpkg` |
| Static analysis | Optional licensed IDA Pro 9+ with official `idapro` support and a compatible Python interpreter; Hex-Rays for pseudocode |
| Agent development | Node.js and npm, only when rebuilding the TypeScript agent |

The Python package includes the compiled Frida agent. Basic SSH, UI and runtime
inspection does not require Node.js, Theos or IDA. Rootless jailbreaks are the
primary target. ARM64e tweak builds require an appropriate Apple toolchain on
macOS. SDKs, proprietary tools and device services are supplied by the operator.

## Quick start

### 1. Install the host dependencies

From the repository root:

```sh
uv sync --frozen --all-extras --no-editable
cp -n examples/ios-decompiler-mcp.toml ios-decompiler-mcp.local.toml
chmod 600 ios-decompiler-mcp.local.toml
```

The lockfile provides reproducible Python dependencies. A non-editable install
also works in managed environments that do not load editable `.pth` files.

### 2. Configure your device

Edit `ios-decompiler-mcp.local.toml`. Set an absolute workspace path, the SSH endpoint,
your key, verified SSH host keys, allowed app bundle IDs and the Frida transport.

```toml
workspace = "/absolute/path/to/ios-decompiler-mcp"
state_dir = ".flex-mcp"

[devices.test]
host = "127.0.0.1"
port = 2222
username = "root"
client_keys = ["~/.ssh/id_ed25519"]
known_hosts = "~/.ssh/known_hosts"
allowed_apps = ["dev.flex.fixture"]
frida_device_id = "replace-with-observed-device-id"
```

The example endpoint assumes an existing local SSH forward; use your device's
actual endpoint. Verify and pin the SSH host key before connecting. Select the
exact device ID returned by `frida_list_devices`. For an existing secured
Frida SSH tunnel, replace `frida_device_id` with
`frida_remote = "127.0.0.1:27043"`; configure one transport per device.

For tweak builds, set `THEOS` or the config's `theos` path. For IDA, configure
`ida_directory` and `ida_python` after completing the vendor's normal licensing
and Python setup. See the comments in the [example config](examples/ios-decompiler-mcp.toml).

### 3. Connect an MCP client

```sh
.venv/bin/ios-decompiler-mcp --config /absolute/path/to/ios-decompiler-mcp/ios-decompiler-mcp.local.toml
```

Configure your MCP client to launch this command with absolute paths. Stdout
carries the MCP protocol; diagnostics go to stderr. See [client setup](docs/CLIENTS.md)
for Codex, Claude Code and Cursor examples.

Run one server per state directory. A config without devices supports host-only
tools such as `server_status`. The server itself does not require a model API key.

## Demos

### Inspect a running app

Open an allowlisted app on the unlocked phone. Call `device_connect` and
`device_list_apps` with `{"device_id":"test"}`, then call `frida_attach`:

```json
{
  "device_id": "test",
  "bundle_id": "dev.flex.fixture"
}
```

Use the returned `session_id` in `ui_snapshot`:

```json
{
  "device_id": "test",
  "session_id": "process_SESSION_ID",
  "depth": 8,
  "max_nodes": 500,
  "limit": 100,
  "include_text": false
}
```

Replace placeholder IDs with observed values. Use `ui_inspect_view` to inspect a
returned view's controller and target-action mappings. Request text explicitly
with `include_text: true` when needed. Call `frida_detach` when finished.
Object and session IDs become invalid after detach, process exit or server restart.

### Capture the current app window

After attaching, call `ui_screenshot`:

```json
{
  "device_id": "test",
  "session_id": "process_SESSION_ID"
}
```

The tool renders the attached application's UIKit window to PNG, using the key
window by default. To select another window, pass a `window_id` returned by
`ui_get_windows`. It returns a native MCP image block plus structured metadata
including `mime_type`, `local_path`, `bytes` and `window_id`. MCP clients with
image support can display the image directly.

Images are saved under `<state_dir>/screenshots/`. Capture is limited to the
selected application's renderable window; system overlays and some protected
or GPU-rendered content may be absent.

### Build and verify a button-title tweak

The [UIKit fixture](examples/UIKitFixture/README.md) provides a button with
accessibility identifier `fixture.button` and an Objective-C action. Build,
install and launch the fixture using that guide, then call `develop_tweak`:

```json
{
  "device_id": "test",
  "bundle_id": "dev.flex.fixture",
  "accessibility_identifier": "fixture.button",
  "replacement_title": "Hello iOS Decompiler MCP"
}
```

The workflow inspects the button, validates an observed controller lifecycle
method, generates an editable Logos project and builds a package. It requires a
unique matching `UIButton` and a supported method signature. Jobs run in the
background by default; retrieve the report using `job_status` and the returned
`job_id`.

At the approval stage, an operator reviews the exact operation in a separate
terminal. Use the report's approval ID and the server's absolute state directory:

```sh
.venv/bin/ios-decompiler-mcp-approve --state-dir /absolute/path/to/ios-decompiler-mcp/.flex-mcp approval_ID
```

Resume `develop_tweak` with `workflow_id` and the granted `approval_id`.
Deployment verification checks the loaded build identity, hook invocation,
observed title and available crash evidence. Uninstallation or a separate
rollback operation requests its own approval.

For the complete interactive inspect → build → approved install → verify →
approved uninstall → restore demo:

```sh
PYTHONPATH=src .venv/bin/python examples/demo.py --config ios-decompiler-mcp.local.toml --device test
```

## Project structure

```text
ios-decompiler-mcp/
├── src/flex_mcp/
│   ├── server.py        # MCP stdio entry point
│   ├── config.py        # Validated configuration
│   ├── core/            # Sessions, state, approvals, jobs and evidence
│   ├── adapters/        # SSH, Frida, IDA, Mach-O and Theos integrations
│   ├── tools/           # Structured MCP tools
│   ├── workflows/       # Tweak development and deployment
│   └── assets/          # Bundled Frida agent and license notices
├── agents/frida/        # Device-side TypeScript source
├── examples/            # Configuration, UIKit fixture and demo
├── scripts/             # Build, documentation and verification utilities
├── tests/
├── docs/
├── pyproject.toml
└── uv.lock
```

The Python namespace `flex_mcp`, default `.flex-mcp` state directory and legacy
`flex-mcp` / `flex-mcp-approve` command aliases are retained for compatibility.
Existing configuration files remain valid.

## Development

```sh
uv sync --frozen --all-extras --no-editable
npm ci --ignore-scripts
npm run typecheck
npm run build
.venv/bin/ruff check src tests scripts examples/demo.py
.venv/bin/mypy
.venv/bin/pytest -q
uv build
```

The agent build uses the official compiler exposed by Frida Python and bundles
`frida-objc-bridge`. After changing Python source or rebuilding the agent,
refresh the non-editable installation before using the installed command:

```sh
uv sync --frozen --all-extras --no-editable --reinstall-package ios-decompiler-mcp
.venv/bin/python scripts/smoke_stdio.py
```

For a source run, use
`PYTHONPATH=src .venv/bin/python -m flex_mcp.server --config /absolute/config.toml`.
Regenerate the tool catalog with
`PYTHONPATH=src .venv/bin/python scripts/document_tools.py`.

Unit and integration tests substitute external device, compiler and IDA
boundaries where needed. SSH/SFTP integration tests use a local loopback server.
Hardware demos require a configured device; optional toolchain checks are
available in `scripts/verify_theos.py` and `scripts/verify_ida.py`.

## Security and scope

- Device and application allowlists constrain targets. Routine inspection is the default; installation, app restarts and other disruptive operations require local approval.
- Approvals bind exact operation arguments and artifacts, expire, and can be consumed once. MCP clients cannot grant their own approvals.
- Tools expose bounded operations with structured errors, audit records and cleanup. Arbitrary shell commands and injected JavaScript are not exposed through MCP.
- UIKit operations run on the main queue. Retained object IDs are session-scoped and can delay object deallocation until detach.
- UIKit and Objective-C are the primary inspection targets. Swift visibility depends on Objective-C interoperability; complete Swift metadata and SwiftUI reconstruction are outside the current scope.
- Runtime/static address correlation requires matching image identity, architecture and segment evidence. Inferred types and pseudocode are labeled accordingly.

Keep local configs, keys, state databases, traces and screenshots private. See
[security and recovery](docs/SECURITY.md) for approval and rollback behavior.

## Documentation

| Guide | Description |
| --- | --- |
| [Client setup](docs/CLIENTS.md) | Connect MCP clients over stdio |
| [Tool reference](docs/TOOLS.md) | Tool groups, required inputs and behavior |
| [UIKit fixture](examples/UIKitFixture/README.md) | Build the example app and run the complete demo |
| [Security and recovery](docs/SECURITY.md) | Permissions, approval scopes and failure recovery |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Device, Frida, IDA and build diagnostics |
| [Upstream review](docs/EXISTING_PROJECTS.md) | Reuse decisions, compatibility and licensing |
| [Third-party notices](THIRD_PARTY_NOTICES.md) | Bundled and external dependency licenses |

## Contributing

Issues and pull requests are welcome. Include the relevant host, iOS, jailbreak,
Frida and toolchain versions when reporting a problem, with sensitive data
removed. Keep changes focused, add meaningful tests for behavior changes, run
the relevant development checks, and update both READMEs when changing user-facing
behavior. Add new tools to the generated reference.

## License

Original iOS Decompiler MCP code is available under the [MIT License](LICENSE). Bundled
code and dependencies retain their own licenses; see [third-party notices](THIRD_PARTY_NOTICES.md).

Built with [Frida](https://frida.re/), [Theos](https://theos.dev/) and the
[MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk), with
inspection concepts inspired by [FLEX](https://github.com/FLEXTool/FLEX).
