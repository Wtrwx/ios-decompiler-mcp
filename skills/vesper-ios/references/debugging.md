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

## UIKit layout diagnosis

Compare the actual media view, its container, overlays and occluding panels in
one observed window coordinate space (`convertRect:toView:` / `screen_frame`).
`frame` uses superview coordinates; a controller's cached media rect can differ
from the rendered view after other hooks/transforms. During animation distinguish
model-layer endpoints from presentation geometry. Read live method encodings
before tracing or implementing a hook: old generated headers can label BOOL,
double and CGRect arguments as `id`. Record the app version and backend class.

A UIButton may implement taps solely through a gesture/block with no UIControl
events or accessibility activation. An unsupported semantic tap is a test
limitation, not evidence that the app action failed. Use an existing app test
hook with a verified selector/ABI when available, and label that observation
separately from physical touch. Keep temporary probes scoped and remove them.
