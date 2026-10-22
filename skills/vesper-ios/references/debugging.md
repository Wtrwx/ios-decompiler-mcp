# Debugging details

`debug_inspect(mode="capabilities")` and `debug_setup(action="check")` report
component availability, not a successful attach. `debug_setup` checks the imported
Frida version, device server, host LLDB, device debugserver, and host classdumpc.
Install only the components needed by the selected backend.

For a stable thread stop or frame locals, request `backend="lldb"` with small
`max_threads`, `max_frames`, `max_variables` and an observed `thread_id` where
possible. No arbitrary LLDB expressions or getters run. Debugserver is bound to
device loopback and reached through the existing SSH connection. Cancellation,
errors and timeouts close this request's LLDB/debugserver and restore execution.

If debugserver starts but attach fails, inspect the returned diagnostic and test
Frida responsiveness. Repeated reinstallation does not fix an incompatible
debugserver/jailbreak combination. Preserve a working device-supplied binary;
Vesper's install action does not overwrite an existing one. A supplied binary must
be an ARM64 iOS Mach-O executable in the configured workspace/state directory.
Apple debugserver and classdumpc binaries are not distributed with Vesper.

`app_logs(action="start", sources=["os_log"], capacity=200)` is the lowest-cost
default. `nslog` adds Foundation log hooks; `stdio` adds stdout/stderr write hooks.
Individual unavailable symbols are reported while working hooks continue.
NSLogv and stdio can expose rendered text; os_log's private encoded argument
buffer is not decoded. This captures the target process, not system-wide history.
`dropped` and `oldest_cursor` explain gaps when the ring wraps. Filtering with no
matches still advances `next_cursor`. Stop the stream to remove hooks and allow
normal idle reclamation.
