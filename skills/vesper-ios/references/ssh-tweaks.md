# SSH build, installation and fallback debugging

Use the project's existing Theos scheme, SDK, deployment target, bundle filter
and private host configuration. Inspect its README/AGENTS.md/Makefile before
building. Local macOS builds can produce arm64e packages that a device-side
toolchain may not support.

## Build and install

Prefer Vesper's `tweak_build` and `tweak_deploy` primitives for platform-created
projects. For an existing project with its own Makefile, run its documented
build command (`make package`, or its explicit CI/SCHEME variant), preserve the
actual exit status, and inspect the produced control metadata/architectures.

If the user uses an SSH build host or device-side Theos, first check that host's
`THEOS`, SDKs, clang/ldid, `make` and target architecture are present. Stage only
the intended source tree in a dedicated directory; use the existing SSH key and
verified known_hosts. Execute the same documented build command remotely with
quoted paths and bounded stdout/stderr. Do not assume a successful SSH connection
means that Theos or an arm64e compiler exists. Keep private host configuration
out of the repository.

Use the existing SSH alias where one is configured. A typical remote build is
`ssh -o BatchMode=yes -o StrictHostKeyChecking=yes BUILD_HOST 'cd /absolute/project && make package'`;
replace the host/path and build flags with observed project settings. For paths
containing quotes or spaces, construct the remote command with `shlex.quote`
instead of concatenating untrusted values. Use `rsync --exclude .git --exclude
.theos --exclude packages` or SFTP into the dedicated build directory, retaining
the project's required sources/submodules. Never sync an entire home directory.
Bound the build by the project's build timeout and save lengthy output to a
local log, returning its exit code and diagnostic tail. Read stderr and stdout;
do not hide a failed build behind a successful `tail` or transfer command.

Transfer the exact `.deb` with SFTP/SCP, verify its SHA-256 at the destination,
then install through the existing project/Vesper deployment mechanism. Device
commands such as `dpkg -i <staged-deb>` are conditional on the configured account
and the project's chosen jailbreak scheme. Retain the previous package for
rollback. A build/install result must be followed by loaded-image/build-marker
evidence and an actual UI/runtime assertion. Observe crashes after restart.

Check `dpkg-deb -f PACKAGE Package Version Architecture` and list its payload
before transfer; inspect the actual dylib with `file`/`lipo` where available.
Hash locally with `shasum -a 256` and remotely with the device's available
`sha256sum`/`shasum`. Discover the package manager path and injection directory
from the configured device rather than hard-coding a rootless prefix. Use
`dpkg-query -W PACKAGE_ID` to confirm the installed version, then verify the
loaded image and behavior in the same observed app process. A package version
alone does not identify a particular rebuild: compare its hash/build marker.
Use an app-specific restart when required by the project; do not respring the
device merely to reload one app. On failure, preserve the log and previous
package, apply the project's rollback, and recheck app responsiveness.

## Diagnose through SSH and Frida

When LLDB fails to attach, keep the app running and use the narrowest working
alternative instead of retrying the same attach indefinitely:

- `app_logs`: bounded target-process os_log/NSLog/stdio ring around the action.
- `debug_inspect(backend="frida")`: observed registers and selected thread stacks.
- `frida_trace_method` + cursor event reads: exact observed selector, limited
  events/arguments/stack depth; remove the hook after the test.
- `objc_query_instances`: selected ivars on known object handles; compare before
  and after a batch action. Do not invent KVC getters.
- SSH package/file checks, loaded dylib UUID/build marker, crash reports from
  the configured crash roots, and persisted verification reports.
- Decrypted Mach-O + IDA when a stripped implementation's logic is needed.

Use an already-installed device log backend for system-wide logs if available;
Vesper's app log ring does not claim system-wide log history. Distinguish a
missing component, a signing/entitlement failure, a debugserver crash and a
target app crash. Restore execution after debugger errors and verify that the
app responds through Frida/UI before continuing the test.
