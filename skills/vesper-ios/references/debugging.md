# Debugging details

`debug_inspect(mode="capabilities")` and `debug_setup(action="check")` report
component availability, not a successful attach. `debug_setup` checks the imported
Frida version, device server, host LLDB, device debugserver, and host classdumpc.
Install only the components needed by the selected backend.

If the app's UI is hung, start with the Frida thread/backtrace backend. Cold
identity verification uses Foundation metadata and does not wait for UIKit's
main queue. No UI observation is needed before sampling. Foundation's NSBundle
is listed in Apple's [thread-safe classes](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/Multithreading/ThreadSafetySummary/ThreadSafetySummary.html).
Frida transport/runtime failure can still prevent sampling; a running-thread
sample does not prove a unique cause. UI handles continue to release on main.

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

For historical crashes on RootHide, the real CrashReporter directories may be
under `/rootfs/var/mobile/Library/Logs/CrashReporter` instead of the SSH root's
`/var/mobile/...`. Deployment verification tries the `/rootfs` equivalents only
when all configured crash roots are inaccessible. An inaccessible directory is
not evidence of a crash-free run. Correlate the target process, timestamp and
termination reason; keep raw reports local and collect only the needed frames.

## UIKit layout diagnosis

Compare the actual media view, its container, overlays and occluding panels in
one observed window coordinate space (`convertRect:toView:` / `screen_frame`).
`frame` uses superview coordinates; a controller's cached media rect can differ
from the rendered view after other hooks/transforms. During animation distinguish
model-layer endpoints from presentation geometry. Read live method encodings
before tracing or implementing a hook: old generated headers can label BOOL,
double and CGRect arguments as `id`. Record the app version and backend class.

Separate photo posts, portrait video and landscape video. A photo placeholder's
large rectangle need not match the rendered image. Check the loaded image size,
content mode and clipping, or verify a screenshot before changing photo layout.
Cache a closed-comment video baseline before native comment animation begins;
layout callbacks during that animation already contain transformed geometry.
Paged feeds preload offscreen cells. Store a stable cell reference with a cached
window rectangle and translate it by the cell's current window origin before
reuse; an offscreen preload coordinate can otherwise move the current video out
of view. Include a scroll into a newly preloaded page in the regression.
Avoid invalidating a view unconditionally from its own layout callback.

A UIButton may implement taps solely through a gesture/block with no UIControl
events or accessibility activation. An unsupported semantic tap is a test
limitation, not evidence that the app action failed. Use an existing app test
hook with a verified selector/ABI when available, and label that observation
separately from physical touch. Keep temporary probes scoped and remove them.
For native action probes, select the currently visible controller and wait for
its transition to finish before another open/close action. A retained but closed
controller is not an active panel. Direct selector calls can bypass the app's
touch debounce and must not be used to infer physical-touch stability.
Record whether a private action ran synchronously inside a Frida callback or
was deferred to the native run loop. Compare those paths if instrumentation
hangs, and reproduce through a real control before attributing the hang to a
tweak. Keep the same geometry assertions when changing the probe mechanism.

For UIKit layout regressions, sample the opening/closing transition as well as
settled rectangles. An unchanged root height does not prove that a description
label or one of its ancestors did not move. Compare visible text/control frames,
ancestor transforms and the actual Tab boundary. Separate video, static image
and Live image cases using observed model flags; a Live image may own a video
player. A UIVisualEffectView on the panel is also insufficient evidence: inspect
opaque nested scroll/cell backgrounds and verify the rendered lower text area.
Test toggle-off restoration and repeated openings without accumulating effects.
Text chips can have their own background and `opaque` flag. Check button title
labels after their parent button finishes layout; it can restore a background
after the label's own callback. Verify reused/expanded reply rows as well.

On RootHide, keep both package and installed-file hashes. If they differ, inspect
the parsed Mach-O slices and all changed ranges before proceeding. The tested
setup can brand padding in the ARM64e __TEXT section segment name with the
observed jbroot identifier and update its code signature. Verify every other
byte, the expected architecture/UUID and the loaded build marker; do not treat
an unexplained mismatch as a successful installation.
