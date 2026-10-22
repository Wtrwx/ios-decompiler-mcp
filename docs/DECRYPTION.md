# Decryption and analysis pipelines

`app_decrypt` adapts the maintained
[AloneMonkey/frida-ios-dump](https://github.com/AloneMonkey/frida-ios-dump)
agent at commit `8395374b3fc254c89e6b6ef67bb8247ac6d1c342` (MIT).
Its recent native-I/O, app-scan and remote-transport fixes were reviewed before
integration. Vesper reuses its own verified app session and AsyncSSH transport;
the upstream Python CLI/Paramiko/frida-tools are not required.

Repository evaluation on 2026-10-23:

| Project | Activity / license | Fit |
| --- | --- | --- |
| [frida-ios-dump](https://github.com/AloneMonkey/frida-ios-dump) | 3969 stars / 738 forks; Python/JS; MIT; code fixes October 21, docs October 22 | Selected: uses the existing Frida deployment; adapted agent tested with 17.5.0 |
| [bagbak](https://github.com/ChiChou/bagbak) | 1511 / 219; TypeScript; MIT; v5.1.2 April 14 | Maintainer marks it deprecated; not selected |
| [unfaird](https://github.com/Lakr233/unfaird) | 63 / 13; Swift; MIT; May 7 | Its documented decrypt runtime requires macOS ≤11.2.3; this host is macOS 15.6.1 |

Metadata and source were read directly with GitHub CLI because web search was
unavailable. Selection considered current code, compatibility and the explicit
deprecation notice as well as activity.

## Use

Call `app_decrypt(device_id, bundle_id)` for a background dump of the main
executable. Read its `job_id` through `job_status`; `job_cancel` cancels work and
cleans the request's incomplete files. `background=false` waits within the
normal tool timeout and is suitable for small files.

For an app whose code lives in frameworks, first request `action="modules"`,
then select an observed `module_name` or exact `module_path`. Only already-loaded
images inside the verified app bundle are accepted. The agent does not initialize
arbitrary frameworks or enumerate other apps to satisfy this operation.

Native file I/O runs on the agent thread. UIKit access remains on the main queue.
The operation copies one Mach-O slice, replaces its encrypted region with
in-process bytes, patches cryptid only after writing, transfers through SFTP,
then validates ARM64 command bounds, zero encryption IDs and the loaded UUID.
The result contains a local `binary_path`, SHA-256, bytes and verification fields.
It never returns executable bytes/base64 in MCP text.

`max_decrypt_bytes` defaults to 512 MiB and can be set up to 2 GiB. Select a
sufficient bound explicitly for large frameworks; unloaded extension processes
and complete IPA packaging are not implemented. Remote temporary files use a
unique name and mode 0600; cleanup attempts remove only this request's file on
completion, failure or cancellation. A lost SSH connection can prevent remote
cleanup. Completed local binaries remain for later analysis.

## Compose tools

- Header declarations: `objc_dump(binary_path=..., class_name=...)` chooses
  the actual host **classdumpc**. It does not substitute class-dump/classdump-ios.
  Static results use a bounded 4-file/16-MiB/300-second cache with source identity
  invalidation. Preview text is opt-in and capped; default output is a local path.
- Live declarations: `objc_dump(device_id, bundle_id, class_name)` uses runtime
  metadata and reuses the Frida session. Current values use
  `objc_query_instances`, preferably known object handles and selected fields.
- Function logic: load `ida_open_binary` through `platform_tool`, then bounded
  symbol/xref/disassembly or Hex-Rays queries. IDA requires the operator's licensed
  installation. Use `ida_resolve_runtime_address` for verified UUID/architecture/
  database SHA-256/segment correlation of a live method IMP.

The [vesper-ios skill](../skills/vesper-ios/SKILL.md) provides these combinations
as conditional workflows, together with SSH tweak builds, installation and
fallback debugging. Missing components return concrete installation guidance;
`debug_setup` reports Frida, LLDB, device debugserver and classdumpc availability.
Installed components alone are not a successful analysis/attachment result.

## Verification boundary

The physical app's 276,080-byte launcher was dumped and verified, then passed
through actual classdumpc and licensed IDA/Hex-Rays. This proves the selected-image
pipeline, not a full dump of the much larger app framework or extensions.
Local tests cover encrypted/malformed/UUID-mismatched results, session pinning,
background cancellation, partial transfer removal, source cache invalidation,
and remote temporary cleanup. Private binaries and generated headers remain
outside Git. See [VALIDATION.md](VALIDATION.md) for device/debugger limitations.
