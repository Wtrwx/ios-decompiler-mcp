# Troubleshooting

| Symptom / error | What to check |
| --- | --- |
| `NOT_ALLOWED` | Use an exact configured device ID and allowed bundle ID. Check transfer roots and workspace/state paths. |
| `SSH_ERROR` on connect | Verify SSH endpoint/forwarding, pinned host key and a readable authorized key. Passwords, SSH agent and interactive auth are deliberately disabled. |
| `SSH_ERROR` on upload | Staging must be a real directory owned by the SSH account, writable and private. Remove an unrelated stale staging directory manually after reviewing its ownership. SFTP extensions must support atomic `posix-rename`. |
| `UNAVAILABLE` for Frida | Install the Python `device` extra on the host. Configure an actual USB ID from `frida_list_devices`, or a secured explicit remote endpoint. Install/start the matching server on the device through the operator's normal process. |
| Frida compatibility warning | Host/server versions should be identical; different major versions are rejected. Discovery can be unverified if the version command is unavailable. Do not silently bypass device protections. |
| `FRIDA_ERROR` / `TransportError: timeout was reached` during `process_attach` | Confirm the selected app's current PID, unlock the test phone and keep that app in the foreground, then retry with matching host/server versions. This failure occurs before the inspection script is loaded. A timeout alone does not establish an app protection or compatibility cause. Restarting an app/service or installing another server requires approval. |
| Frida foreground lookup returns no application | This lookup returned no app on the tested iOS 16.0 device even after the operator opened Douyin and attachment/UI inspection succeeded. Verify the selected bundle/PID and attempt normal allowlisted attachment; do not treat a null foreground lookup alone as evidence that the operator has not opened the app. |
| Device reports `iPhone11,8` instead of ARM64 | `uname -m` on iOS reports the hardware model. Current discovery records that separately and uses `hw.cputype` for CPU architecture. The selected Mach-O's subtype determines ARM64e build selection. |
| App is not running | Launch it manually or request `device_launch` and grant that exact operation locally. Verify bundle ID and observed PID. |
| `SESSION_INVALID` / stale view ID | App exit, detach, timeout or host restart invalidates handles. Reattach and take a new snapshot. Never reuse a pointer from a prior session. |
| Object limit reached | Detach to release retained references, reattach, and narrow snapshot/search depth. The registry caps retained objects at 2048 per agent. |
| No matching button / no controller | Use one unique accessibility identifier on a UIKit UIButton. The autonomous recipe requires a controller observed in the responder chain and a validated lifecycle ABI. SwiftUI-only elements may not have such views. |
| Unknown ABI or build signature mismatch | Reinspect type encodings and use a supported recipe. The generator refuses uncertain types and does not guess aggregate/object return ABIs. |
| `BUILD_FAILED` | Read `tweak_get_build_errors` and the saved build log. Check THEOS, `make`, compiler, SDKs, Logos, signing and deployment target. Linux cannot build the modern ARM64e recipe. |
| Clang module-cache permission error | The tweak adapter uses `state_dir/compiler-cache`. For the fixture/manual make, set `CLANG_MODULE_CACHE_PATH` to a writable directory. |
| `APPROVAL_REQUIRED` | Review generated files, checksum, target, restart and recovery scope; run the separate local CLI against this server's state directory. |
| `APPROVAL_INVALID` | Grant expired, was consumed, or no longer matches the session/content/options. Invoke the operation without an ID to obtain a new exact request; workflow resumption does this automatically. |
| `DEPLOY_FAILED` | Inspect `tweak_get_logs`, saved deployment rollback status, dpkg account permissions, package database and injection substrate. Successful package installation alone does not prove loading. |
| Installed but not verified | Check build marker, hook invocation, unique button/title and crash results separately. Reentering the view may be needed for a lifecycle hook; the workflow can restart only when authorized. Failures roll back. |
| Crash scan unavailable | Configure readable `crash_roots` for the device's layout and SSH account. Verification will not pretend an inaccessible directory contains no crashes. |
| IDA unavailable | Set `ida_directory` and a Python executable compatible with that IDA installation. Require official idapro/idalib 9+, valid license and its normal vendor configuration. The server never changes licensing automatically. |
| IDA exits without readiness | Inspect the bounded diagnostic in the structured error. Run `scripts/verify_ida.py` with an operator-provided Mach-O; on sandboxed hosts, native IDA registry/license access may require normal application permissions. |
| Pseudocode unavailable | A matching processor decompiler and license are optional. Metadata, disassembly and xrefs can still work. Pseudocode is inferred by Hex-Rays. |
| Static/runtime identity mismatch | Use the exact same binary build, architecture and database. UUID mismatch or absent evidence means no match; do not adjust slides by guesswork. |
| Duplicate server / state lock | Stop the other MCP server or give this client its own state directory. The approval CLI can coexist with one server. |
| `ModuleNotFoundError: ios_decompiler_mcp` in an editable install | Reinstall with `uv sync --frozen --all-extras --no-editable`. Some managed macOS environments hide editable `.pth` files. Source runs can use explicit `PYTHONPATH=/absolute/repo/src`. |
| Tests cannot bind loopback | The SSH integration tests require permission to listen on `127.0.0.1` only. Grant local test networking; no iPhone or external server is needed. |

After a host crash, consult `server_status.recovery_required` and
[the recovery procedure](SECURITY.md). Do not delete cached state/packages until
you have restored and checked the device. The server never automatically resprings
the phone, reboots it, installs services or modifies app protection settings.
