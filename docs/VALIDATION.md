# Implementation status and validation

The fixture identifiers below belong to the artifacts originally tested. The
current example uses `dev.iosdecompiler.fixture` and `DecompilerFixture` class
names. Rebuild the example and tweak before testing the current source on a device.

Recorded 2026-10-22. Read-only physical-device inspection passed on Douyin:
44 actual MCP calls across 27 tools, including attachment, UIKit inspection,
Objective-C metadata, method traces/stacks and cleanup with the same app PID.
Tweak installation and its end-to-end behavior/restoration remain unverified.
No package was installed and no app was restarted.

## Milestones

| Milestone | Implemented | Validation boundary |
| --- | --- | --- |
| 1: MCP foundation | Official SDK stdio server, 61 typed tools, structured results/errors, SQLite metadata, allowlists/approvals/audit, jobs/cancellation, AsyncSSH, Frida lifecycle and app discovery | Real MCP initialization/tool discovery/invocation; real ephemeral SSH/SFTP server; physical pinned SSH, Frida app/process discovery, attachment and detach passed. |
| 2: FLEX-style inspection | Main-queue UIKit windows/scenes/hierarchy, frames/bounds/visibility, controller responders, constraints, targets/actions, hit testing, bounded search, PNG capture; ObjC metadata, IMPs, instances and headers | Physical Douyin windows, bounded hierarchy, view inspection, nonempty constraints, responder chain, hit testing, class dump, positive property/ivar enumeration and header generation passed. Screenshot rendering and heap enumeration remain unverified on hardware. |
| 3: Logos development | Editable app-scoped projects, typed recipes, live ABI validation, SDK/architecture selection, compile/package diagnostics, exact-content deployment approval, package/dylib checksums, restart, runtime marker/count/title verification, bounded deterministic repairs and rollback | Real rootless ARM64 fixture app and tweak compile/package. Mocked full workflow covers approval, changed title, uninstall/restoration, failed install, failed behavior, stale artifacts, expiry and cancellation. Physical end-to-end demonstration pending. |
| 4: advanced analysis | Bounded Frida entry/leave events, call counts, scalar arguments/returns, stacks, enable/disable/export; isolated official IDA worker, function/disassembly/xref/symbol/decompile queries; UUID/architecture/ASLR mapping | Physical entry/leave traces, BOOL returns matching window state, stacks, pause/resume, export and unhook passed. A live UIKit IMP/image UUID was observed. Real licensed SDK returned host binary metadata, functions, disassembly, xrefs and Hex-Rays pseudocode. Live IMP-to-IDA correlation remains unverified. |
| 5: hardening/docs | Tests, Ruff, mypy, lockfiles, source/wheel distribution with bundled bridge notices, examples, client setup, limits, troubleshooting, recovery and CI configuration | Local checks executed as below. Linux and remote CI matrix have not been executed in this session. |

## Executed host checks

- `pytest`: **41 passed**, with an ephemeral loopback SSH/SFTP listener. It
  exercises pinned-host rejection, public-key auth, pooling/reconnection,
  canonical transfer bounds, timeouts/output caps, session invalidation, audit
  redaction, one-use approvals, background cancellation and host-restart state.
  Tests also exercise MCP image content, PNG preservation beyond text limits,
  Debian payload/control restrictions and bounded decompression before parsing.
- `ruff check src tests scripts examples/demo.py`, `mypy`, `npm run typecheck`
  and `npm run build`: successful. The official Frida compiler builds the
  injected bundle with the pinned separate Objective-C bridge.
- Real Theos fixture application: `dev.flex.fixture_0.1.0_iphoneos-arm64.deb`.
  Build products are in ignored `.ios-decompiler-mcp/fixture-packages/`.
- Real generated title tweak: ARM64, rootless, SDK 18.1, target iOS 15.0,
  app-only `dev.flex.fixture` filter. Latest recorded package at validation:
  `.ios-decompiler-mcp/projects/project_8785cab917824954aefc01148069915d/builds/build_64077f5637c84ae4a85aa9e88937d8da/dev.flex.fixture.title_0.1.0_iphoneos-arm64.deb`.
  SHA-256: `95b41bbb5a5184900e74779428d40d54e3993c6865dc99fd25dd971ec05d4650`.
  The build completed Logos preprocessing, compilation, linking, signing and
  packaging. A sandbox `sysctl` warning and obsolete linker flag warning were
  nonfatal. Initial Clang cache permission errors were fixed with a managed
  writable module cache.
- Real IDA SDK: installed application directory `IDA Professional 9.1.app`;
  its `idapro.get_library_version()` reports `[9, 0, 250226]`. Worker used the
  installation-compatible Python 3.13 interpreter; MCP host used Python 3.12.
  The exact thin input bytes were preserved and the database input SHA-256 was
  verified. First function at `0x4000` has a data xref from `0x4500`; Hex-Rays
  inferred `objc_getClass` and `MSHookMessageEx` calls for the generated hook.
  Normal host access was required for IDA's registry/license files; sandboxed
  access initially timed out. No licensing workaround was used.
- Python wheel/source distribution build: successful. The wheel includes the
  agent and full bridge license texts. Installed-wheel MCP smoke: successful,
  started from `/private/tmp` with `PYTHONPATH` removed, discovered all 61 tools
  and called `server_status`. The installed `ios-decompiler-mcp --version` returns `0.1.0`
  outside the repository. This verifies actual packaging rather than an editable
  source-path import.

Host environment: macOS 15.6.1 ARM64, Xcode 16.1, installed Theos and iOS SDKs;
project Python 3.12.12, MCP 1.30.0, Frida 17.24.3, AsyncSSH 2.24.1,
LIEF 0.17.6, TypeScript 5.9.3 and Objective-C bridge 8.0.6. Exact host dependency
resolution is in the committed lockfiles.

## Physical device test: Douyin

The operator supplied SSH at `127.0.0.1:12222`. Existing pinned Ed25519 host-key
and public-key authentication worked. An SSH tunnel to the already running
Frida service was created on host port 27043; no device service was installed
or restarted.

Observed environment:

- Hardware model `iPhone11,8`; CPU type `16777228`, subtype `2`; iOS `16.0`;
  rootless prefix `/var/jb`; SSH UID `0`.
- Installed Frida server `17.5.0`.
- Selected app `com.ss.iphone.ugc.Aweme`, version `39.2.0`, build `392014`,
  observed PID `8119` throughout the recorded tests.
- Actual MCP stdio discovery returned all 61 tools. Two successful inspection
  runs completed 31 and 44 MCP calls respectively, using the matching isolated
  host client `17.5.0`. Both finished with the same observed app PID `8119`.
- The expanded 44-call run covered 27 distinct tools. It observed 2 windows,
  1 scene, and 70 view nodes with a depth limit of 12. The snapshot reports
  truncation; this is a bounded sample, not a complete app UI tree.
- Observed custom button class `AWENormalModeTabBarGeneralButton` and controller
  `AWENormalModeTabBarController_hmd_subfix_`. The controller class dump and
  generated header succeeded. A responder chain contained 9 objects.
- Native property/ivar entry readers were exercised with `UIView`, reporting
  totals of 772 properties and 42 ivars, returning a page of 10 each. A bounded
  search found a view with 7 constraints and returned actual constraint entries.
- A temporary observation hook on `UIWindow.isKeyWindow` recorded 2 calls,
  4 entry/leave events and 2 stack traces. BOOL returns `[1, 0]` matched the
  window query's key-window flags. Hook listing, pause/resume and trace export
  succeeded. The hook was removed, its list became empty, and the agent detached.
- The observed UIKitCore method encoding was `B16@0:8`; its loaded Mach-O UUID
  was `7b942fa4-cb76-3375-9972-f58c14492fb4`, image architecture ARM64e.
  No IDA database match is asserted from that runtime metadata alone.
- The default crash roots and their `/private/var` equivalent returned
  `SFTPNoSuchFile`. Absence of app crashes cannot be verified.

Two earlier attachment attempts timed out, first with client `17.24.3`, then
with matching `17.5.0`. After the operator unlocked the phone and opened Douyin,
matching-client inspection passed twice. The cause of those earlier timeouts
has not been established. Frida's foreground lookup still returned no application
even during this successful test, so a null lookup is not a reliable readiness
gate on this setup. Client `17.24.3` attachment was not retested after that point.

Private raw MCP reports are saved under
`.ios-decompiler-mcp/douyin-device/hardware-reports/` (mode 0600). Successful reports are
`20261022T144920Z.json` and `20261022T145356Z.json`. No UI text,
screenshots, account data or unrelated app contents were collected.

This hardware test found an actual discovery bug: iOS `uname -m` returns a
hardware model rather than an ISA. Discovery now stores the model separately,
derives CPU architecture from `hw.cputype`, and leaves ARM64e build selection
to the selected Mach-O. The corrected ARM64 result was checked on the phone.
Native attachment, script creation/loading and agent initialization failures
now include a `phase` diagnostic. Two regression tests were added.

`scripts/verify_device.py` runs the remaining inspection suite through the
real MCP transport. It requires an already running allowlisted app, captures
no UI text, performs a temporary read-only `UIWindow.isKeyWindow` trace,
removes its hook and detaches, and checks that the same app PID remains.
Its overall pass flag is set only after all of those checks succeed. Both
successful Douyin reports have `passed: true` and `same_pid_after_detach: true`.

To reproduce with the ignored local configuration, keep an SSH forward running in
a separate terminal, unlock the phone and open Douyin, then run the inspection:

```sh
ssh -N -L 127.0.0.1:27043:127.0.0.1:27042 -p 12222 -o BatchMode=yes -o StrictHostKeyChecking=yes root@127.0.0.1
```

```sh
PYTHONPATH=.venv/frida-17.5.0:src .venv/bin/python scripts/verify_device.py --config ios-decompiler-mcp.local.toml --device iphone --bundle com.ss.iphone.ugc.Aweme
```

The matching-version client is isolated in `.venv/frida-17.5.0`. The normal
locked host environment remains on Frida 17.24.3; the supported dependency range
now permits the physically tested 17.5.0 without changing that default lock.

## Physical verification still required

Screenshots, heap-instance enumeration, package injection substrates, restarts,
crash timing, actual title changes and actual restoration remain **unverified**.
The five sampled Douyin tab buttons have no accessibility identifier and returned
empty target-action lists. The current autonomous title recipe requires a unique
identifier; it cannot directly use these sampled controls. No identifier was
invented and no device UI state was modified to bypass this precondition.

1. Identify readable crash-report roots and verify the device's injection
   substrate before package verification. Do not substitute an unrelated empty
   directory for crash evidence.
2. Build the fixture following `examples/UIKitFixture/README.md`. Have the
   operator authorize installation, register and launch it. Confirm `Original`
   and deterministic label updates on taps.
3. Update the ignored local configuration to allowlist the fixture and configure
   its staging/download/crash roots while preserving the verified connection.
4. Run `examples/demo.py` through the real transport. Review generated code and
   locally approve deployment/restart. Check the exact marker, invocation count,
   observed title and crash status in the returned report.
5. Locally approve uninstall/restart. The script must observe `Original` again
   before reporting PASS. Save the report and record the exact iOS/jailbreak,
   device architecture, substrate and Frida versions tested.
6. Exercise lifecycle exit/reattach, screenshot rendering, and IDA mapping
   using the exact app binary UUID. Then test a controlled installation/behavior
   failure and check recovery on the same disposable test target.

These are remaining validation steps, not claims that the tests ran. App launch,
termination, install, uninstall and uploads always require actual authorization.

## Partial and planned capabilities

- The high-level workflow implements the identified-button title recipe. It
  diagnoses load/invocation/behavior/crash failures and rolls back. Compilation
  repair is limited to two supported missing-header cases, with a configured
  retry cap; it does not invent signatures or perform general LLM code repair.
  Other user-edited source can be rebuilt through lower-level tools.
- Objective-C-visible Swift classes can be inspected. Pure Swift metadata,
  SwiftUI semantic trees and full metadata reconstruction are not implemented.
- Rootful project generation and ARM64e selection exist; their actual builds,
  installation ABI and hardware compatibility remain unverified here. Linux
  modern ARM64e generation is rejected. Only ARM64 rootless packages were built.
- Live IDs retain objects, capped at 2048, which can delay deallocation. A host
  crash can leave retains until app exit. Inspection may briefly pause the app.
- A built-in inspection/tracing agent is loaded per attachment and unloaded on
  detach. Arbitrary custom scripts, raw shell, method replacement through Frida,
  private touch injection and app-protection bypasses are not exposed.
- Crash evidence consists of app-matching filenames/mtimes in configured roots;
  unified log contents and crash report bodies are not harvested. Delayed crash
  creation can outlast the bounded verification window. Runtime tracing and
  managed package-operation logs are available.
- Debian gzip/xz/lzma/uncompressed archives are supported; generated builds force
  gzip. Zstandard packages and maintainer scripts are rejected by default.
- Stdio is implemented. Streamable HTTP, multi-user authorization, generic
  privileged device maintenance and cross-host shared sessions are not implemented.
- CI is configured for Python 3.11/3.12 on macOS/Linux, but only this macOS host
  has been run locally. There is no universal jailbreak compatibility claim.
