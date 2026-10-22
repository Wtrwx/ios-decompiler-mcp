# Upstream review

Reviewed 2026-10-22 using repository READMEs, license files, current GitHub metadata,
the installed Theos tree and the installed IDA 9.1 `idapro` API. Push dates are
repository activity signals, not evidence of release quality or device compatibility.
No implementation source from the comparison MCP projects is copied into this project.

| Project / activity at review | Available features | Reuse decision and constraints | License considerations |
| --- | --- | --- | --- |
| [FLEX](https://github.com/FLEXTool/FLEX), pushed Oct 18, 2026 | In-app view explorer, object/runtime inspection, layout and debugging UI | Use its capability model as a reference; implement structured queries using UIKit/runtime APIs. Embedding the framework would add an in-app UI and distribution burden. Main-thread access remains essential. | Its [license](https://github.com/FLEXTool/FLEX/blob/master/LICENSE) is BSD-like with an additional prohibition on including FLEX in App Store submissions. No FLEX code or binary is bundled. |
| [Frida](https://github.com/frida/frida), pushed Oct 20, 2026 | Native instrumentation, USB/TCP devices, sessions, RPC, interceptors, symbols and stacks | Use maintained `frida-python` directly. Frida 17 moved the Objective-C bridge out of core: bundle the official [`frida-objc-bridge`](https://github.com/frida/frida-objc-bridge). Use current module instance/global-export APIs. Device/server compatibility and injection rights remain prerequisites. | [wxWindows Library Licence 3.1](https://github.com/frida/frida/blob/main/COPYING), LGPL with an exception; preserve bundled bridge notices and license texts. |
| [frida-ios-mcp](https://github.com/YPYT1/frida-ios-mcp), pushed Jul 21, 2026 | TypeScript stdio MCP, UI probes, persistent sessions/daemon, touch and application-specific scripts | Useful reference for session invalidation and bounded operations. Its USB/spawn-first and application-specific behavior do not fit a general read-only server. No dependency or source reuse. Network/credential extraction and protection workarounds are excluded. | GitHub did not report a license and `/license` returned 404 at review. Treat reuse permission as unestablished; public visibility alone is not a license. |
| [re-ios](https://github.com/gyh20062008-commits/re-ios), pushed Jul 9, 2026 | Python MCP, IPA/Mach-O metadata, Objective-C/Swift symbols, Frida operations | Reference integration patterns; use portable maintained APIs rather than its macOS CLI assumptions. DRM extraction and application-specific transaction hooks are outside scope. Missing here: secure SSH lifecycle, UIKit queries and Theos deployment transaction. | MIT according to current repository metadata. No source copied. |
| [re-mcp](https://github.com/jtsylve/re-mcp), pushed Sep 18, 2026 | Headless IDA/Ghidra, multi-database supervisor/worker architecture, decompile/xrefs/symbol queries | Confirms official `idapro`/idalib is the supported headless route on IDA 9+. Use an isolated worker per database with the SDK directly to avoid coupling to another MCP's changing tool schema and Python 3.12 minimum. | Apache-2.0; process integration is possible. No source copied. IDA is separately licensed. |
| [Theos](https://github.com/theos/theos), pushed Oct 8, 2026 | Logos preprocessing, iOS compilation, rootless packaging and Debian packages | Execute installed Theos as an external compiler, generate original project files. Discover SDK versions; use `THEOS_PACKAGE_SCHEME=rootless`, `iphoneos-arm64` and the scheme's install prefix. No `make install` or global injection. New work: signature checks, approval binding, runtime evidence and rollback. | [GPL-3.0-or-later](https://github.com/theos/theos/blob/master/LICENSE.md); upstream explicitly says generated projects are not derivative works and templates are license-free. No compiler is vendored. |

Other evaluated options:

- [Official Hex-Rays IDA MCP](https://github.com/HexRaysSA/ida-mcp) now requires
  IDA 9.4+ and uses IDA Nexus. It is the upstream-recommended MCP option, but does
  not support the locally installed 9.1. iOS Decompiler MCP's optional SDK worker targets
  official idalib in IDA 9.0+, with capabilities checked at runtime.
- [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) is MIT, active as
  of Sep 26, 2026, offers headless per-database workers, and recommends the official
  server. No hard dependency on its independently evolving MCP interface.
- [Apple Objective-C runtime](https://developer.apple.com/documentation/objectivec/objective-c_runtime)
  and the bridge's documented `ObjC.api`, `ObjC.classes`, `ObjC.choose` and
  `ObjC.schedule` cover runtime metadata and main-thread dispatch. Pure Swift
  metadata reconstruction, private touch injection and arbitrary object getters
  are not prerequisites.
- [LIEF](https://github.com/lief-project/LIEF) (Apache-2.0) provides maintained,
  portable Mach-O/fat-binary parsing, UUIDs, CPU subtypes and segment ranges. Prefer
  it to a handwritten host Mach-O parser or macOS-only `otool` output parsing.
- [AsyncSSH](https://github.com/ronf/asyncssh) (EPL-2.0 OR GPL-2.0-or-later) provides
  maintained asyncio SSH/SFTP, timeouts and host-key checking. It is consumed as a
  dependency, not copied. Preserve dependency notices when distributing packages.
- [Official MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk/tree/v1.x)
  (MIT) supplies stdio lifecycle, tool discovery, cancellation and structured results.
  Pin the stable v1 line (`mcp<2`) and resolve exact versions in `uv.lock`.

Remaining original implementation: stable process-scoped object identities,
bounded UI searches, safe trace events, allowlists/approvals/auditing, editable
Logos recipes, build diagnostics, transactional deployment and evidence-based
behavior checks. Upstream capabilities do not imply that these integrations have
passed a physical-iPhone test.
