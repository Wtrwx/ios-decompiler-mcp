---
name: vesper-ios
description: Use Vesper for iOS reverse engineering, UIKit automation, live Objective-C values, decryption plus classdumpc/IDA, SSH tweak builds and installation, and LLDB/Frida/log debugging.
---

# Vesper iOS

Use the connected `vesper` MCP server. Work with the configured device and app;
reuse their session. Vesper's focused catalog exposes the common operations.
For an advanced primitive, request its exact schema with
`platform_tool(name="…", action="schema")`, then call it through
`platform_tool(name="…", arguments={…})`. Load only the schema needed now;
`tool_profile="full"` is available for clients that need the entire catalog.

## Choose the least expensive observation

- Current controls: `ui_capture(device_id, bundle_id, mode="summary")`.
  Text requires `include_text=true`. PNG requires `mode="screenshot"` or `"both"`.
  No preliminary enumeration, attach, or window query is needed.
- Read `next_cursor` from the same snapshot with `ui_snapshot`; this is a host
  cache read. Omit `snapshot_id` to observe the current UI after a change.
- Read selected instance parameters with `objc_query_instances(object_ids=[…],
  field_names=[…])`. Prefer leased handles already observed in the UI. Class-name
  heap discovery is useful when no handle exists, but costs more and may pause
  the app. Page its snapshot without scanning again. Expired handles require a
  fresh observation, rather than retaining everything indefinitely.
- Request controller ownership, constraints, targets, inherited methods or
  nested values only when they resolve the current question.

## Automate a test

Batch related `tap`, `back`, `input_text`, `scroll`, `assert`, and `wait_for`
steps in `ui_automate`; use one `after_capture` when a final observation helps.
Prefer a leased view ID or a unique accessibility selector. Match by class/text
only after observing the actual UI; text selectors require explicit text reads.
The batch stops at its first failure. An uncertain timeout can occur after an
action took effect: inspect the current UI before deciding whether to repeat it.

UIKit actions dispatch controls/accessibility, pop/dismiss controllers, set text
with change events, and adjust scroll offsets. They do not synthesize raw HID
touches, gesture trajectories, or keyboard composition. A custom gesture-only
view can be inspected but may require an existing test hook for activation.
For a vertical paged feed, use `scroll` with `pages=1` (next) or `pages=-1`
(previous), optionally `animated=true` and a bounded `settle_ms`. The device
reads its current viewport height; do not hardcode screen pixels or Tab Bar
height. Reuse the observed scroll view ID to avoid another tree search. Verify
page identity/playback where relevant; content offsets alone do not prove play.

For a tweak regression, observe the relevant property/action before and after
the change, then assert the expected state. For builds/deployment, read
[references/tweaks.md](references/tweaks.md). Report the observed behavior;
successful compilation or package installation alone does not verify a tweak.

## Choose a metadata backend

`objc_dump` automatically chooses `classdumpc` for a local `binary_path`, or
runtime for `device_id`, `bundle_id`, and `class_name`.

- Use classdumpc for offline Mach-O headers without device work. Set `class_name`
  or `class_filter` when possible. It returns a local file; `preview_chars` is
  opt-in. This is the host **classdumpc**, not class-dump/classdump-ios.
- Use runtime for loaded/decrypted classes, current method encodings and live
  object values. Static headers cannot provide current instance parameters.
  An encrypted/stripped file may require runtime metadata.
- For offsets, methods or ownership, load only the needed `objc_get_*` or
  `ui_inspect_view` schema through `platform_tool`.

## Combine decryption, headers and disassembly

For encrypted app binaries, use `app_decrypt` with an observed loaded module.
The result is a local verified Mach-O, not a header or IPA. Chain its
`binary_path` into classdumpc or IDA according to the question. Read
[references/analysis-pipelines.md](references/analysis-pipelines.md) for
decryption → classdumpc → IDA → runtime workflows and identity checks.

## Debug and collect logs

Use `debug_inspect` with the default Frida backend for immediate threads,
registers and bounded stacks. These sample running threads; they are not a
consistent stop of the entire process. Select `backend="lldb"` for stopped
inspection and locals. LLDB detaches/resumes after the bounded request.

If a required component is missing, use `debug_setup(action="check")` and follow
its `next_actions`/component `install_hint` for the selected backend. Device
debugserver can be installed with `debug_setup(action="install")` from matching
local Apple device support. `repair` reuses a device-provided signing profile.
Installed components do not prove attachment works: verify with an inspection.
Keep the existing Frida deployment/version pairing.

For logs, start `app_logs` once, read with `after=next_cursor` and a narrow
`contains`/`level` filter, then stop the stream when finished. An active stream
pins its session. The device ring and each page are bounded. `os_log`/`NSLog`
records may contain format strings rather than expanded arguments; do not
infer values from placeholders. Read
[references/debugging.md](references/debugging.md) for backend failure handling.
For SSH build/install/debug and alternatives when LLDB cannot attach, read
[references/ssh-tweaks.md](references/ssh-tweaks.md).

Use native MCP image content for display. Keep full headers/log files local;
return selected findings and paths. Measure actual response bytes when reporting
token savings; distinguish server time, MCP round trips and model/viewer waits.
