# Third-party notices

Original vesper code is MIT licensed. Dependencies retain their own licenses.

The compiled `src/vesper/assets/agent.js` includes the unmodified official
[`frida-objc-bridge` 8.0.6](https://github.com/frida/frida-objc-bridge) dependency,
maintained by Ole André Vadla Ravnås and Frida contributors. Its npm manifest
declares `LGPL-2.0 WITH WxWindows-exception-3.1`. The full GNU Library GPL 2.0
and wxWindows Library Licence 3.1 texts are distributed in
`src/vesper/assets/licenses/`, including in the wheel. Upstream's wxWindows
text is preserved verbatim from [Frida COPYING](https://github.com/frida/frida/blob/main/COPYING).
The original dependency source is available from the exact npm version recorded
with integrity hashes in `package-lock.json`; `npm ci` restores it into
`node_modules/frida-objc-bridge`. Rebuild instructions are in the README.
The readable bundled module bodies are also present in `assets/agent.js`.

Runtime dependencies are installed separately: MCP Python SDK (MIT), Pydantic
(MIT), AsyncSSH (EPL-2.0 OR GPL-2.0-or-later), Frida (wxWindows Library Licence
3.1), LIEF (Apache-2.0), and their transitive dependencies. Their installed
distribution metadata contains their license notices. Node development tools
include TypeScript (Apache-2.0) and Frida Gum declarations (MIT).

Theos is an external GPL-3.0-or-later compiler, not vendored. Its license states
that generated projects are not derivative works of Theos. IDA/Hex-Rays and the
Apple SDKs are separately licensed operator-provided installations. No IDA,
FLEX framework, Apple SDK or proprietary app binary is redistributed here.
No implementation code from the compared MCP projects is copied.

The decryption agent adapts `AloneMonkey/frida-ios-dump` at commit
`8395374b3fc254c89e6b6ef67bb8247ac6d1c342` (MIT, copyright Alone_Monkey).
Source: https://github.com/AloneMonkey/frida-ios-dump/blob/8395374b3fc254c89e6b6ef67bb8247ac6d1c342/dump.js
The copied license is in `agents/frida/vendor/frida-ios-dump.LICENSE` and
`src/vesper/assets/licenses/frida-ios-dump-MIT.txt` in the wheel.
Vesper adapts module selection, lazy invocation, private temporary files, size
bounds, session reuse and verified SFTP transfer. It does not force framework
loading or package an IPA. Apple debugserver and classdumpc are not bundled.
