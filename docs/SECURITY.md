# Security, permissions and recovery

## Trust boundaries

The operator controls the host workspace, configuration, SSH account, iPhone,
Theos installation and optional IDA license. MCP clients are constrained to
declared semantic tools. This is a local stdio service, with no public HTTP
listener. No raw shell, unrestricted RPC, arbitrary JavaScript loader, password
authentication, host-key auto-accept, or service-installation tool is exposed.
An agent with separate unrestricted access to the operator's filesystem could
edit approval state directly; the local CLI is a boundary for MCP clients, not
a sandbox for arbitrary programs running as the operator.

Device IDs and app bundle IDs are explicitly allowlisted. Application discovery
and process enumeration filter to those apps. Frida attachments validate the
observed app PID and injected bundle identity. SSH uses key authentication and
the configured known_hosts file with agent/password/keyboard-interactive auth
disabled. Shell arguments are quoted from validated semantic inputs; rootless
tool paths are added explicitly to PATH.

## Approval lifecycle

An operation without a grant returns `APPROVAL_REQUIRED` with its full scope and
approval ID. The operator separately runs `vesper-approve`, reviews the scope,
and types `approve`. Only the local CLI grants requests. A grant is valid for
ten minutes, exact-argument bound, single-use and consumed atomically in SQLite.
Changing the session, artifact bytes, device, restart option or previous package
requires a new request. Nothing is granted by a timeout or an unanswered prompt.

`device_upload`, app launch/termination, package installation, manual rollback
and uninstall require approval. Read-only device calls, local project editing
and compilation do not. Frida attach loads an inspection agent; hooks observe
calls without replacing implementation results. Theos build runs trusted local
Makefiles as the operator, so review externally modified project files.

The workflow requests deployment approval only after generating reviewable
source and a package. The scope includes a bounded recovery policy: on failure,
remove a new managed package or restore the cached preceding managed artifact,
and restart only when approved. That recovery is part of the reviewed operation;
it does not require an additional prompt during a failure. Independent later
uninstall/rollback operations need their own grants.

## Files, packages and recovery

Local file inputs are resolved within workspace/state roots. Device downloads
can create only new files in `state_dir/downloads`; they cannot overwrite the
approval DB, configuration, source or existing files. Remote transfers stay
within configured roots, recheck canonical paths, reject staging symlinks and
foreign owners, use a private staging directory and exclusive random temporary
files, and bound transfer sizes. Approved generic uploads check the actual
stream hash before renaming. Deployment verifies the remote package hash too.

Packages must contain exactly the expected dylib and its one-application filter
plist. Maintainer scripts, global filters, symlinks, traversal and extra payloads
are rejected. Package name/version/architecture and source fingerprints are
checked. Uploaded and installed dylibs are hashed. An installed unmanaged package
cannot be silently replaced. A previous managed package must still match its
cached artifact before an upgrade is allowed. An old or superseded deployment
cannot uninstall a different current artifact.
Verification and recovery serialize with device mutations. Automatic recovery
rechecks the current deployment and installed bytes, so a late failing workflow
cannot remove a newer approved deployment.

Cancellation waits for an active installation to settle before recovery, rather
than racing dpkg. Failed verification triggers recovery and reports its result;
package restoration is distinct from verified restoration of app behavior.
The physical demo checks the original title again after uninstall.

On a host/process crash, automatic actions cannot establish the device's final
state. On restart, live sessions are invalidated and unfinished deployments are
marked `interrupted`. `server_status.recovery_required` identifies those records.
Check package status and device state first. Manual `tweak_rollback` or
`tweak_uninstall` obtains a fresh approval and proceeds only if the installed
version and dylib still match the interrupted record. A partially broken dpkg
database or changed artifact requires explicit operator maintenance outside MCP;
there is no generic privileged repair shell. Keep the state directory and cached
previous packages until recovery is complete.

## Data and execution limits

UI text is opt-in, secure text fields redact their value, metadata queries do not
read object contents, and trace arguments are
bounded scalars/addresses. Screenshot requests can contain visible app data and
must be deliberate. The workflow explicitly captures its selected button/title
and bounded nearby hierarchy as evidence. Do not select unrelated private UI.

Secret-key fields, bearer values, common credential patterns and private-key
blocks are redacted in results/events/audits. This is best-effort filtering, not
a guarantee that all sensitive free text or image pixels can be recognized.
`objc_query_instances` and explicit `objc_inspect_object(include_values=true)`
read bounded ivars. Sensitive ivar/dictionary names are checked before reading
their values; unknown objects return leased references. Only known Foundation
string/number/collection accessors are used for bounded value serialization;
arbitrary getters/descriptions and raw pointer dereferencing are not exposed.
Native/Swift layouts and concurrent object mutation can still make reads
unavailable or inconsistent; this is best-effort runtime inspection.

Audits store tool outcome and scoped approval metadata, not raw tool arguments.
State files are private to the local operator. Delete/export them deliberately
under the operator's data-retention policy.

Tools have execution deadlines. Process output, file sizes, object IDs, hooks,
sessions, worker slots, jobs, events and UI traversals have caps. Event cursors
include loss counts. Native object references are retained for identifier safety,
reference-counted across expiring snapshot/operation leases, and released after
their final lease ends or on detach. Active batched operations hold their input
references across waits; RPCs, hooks and workflows protect sessions from idle
reclamation. Retaining can delay app object deallocation. An abrupt
host death may prevent release until the target process exits. Main-thread
inspections and heap scans can briefly pause the app. These tools are debugging
instrumentation and should be used on an isolated test device.

Crash checks inspect only app-matching filenames and timestamps in configurable
crash roots, not personal log contents. Inaccessible roots produce an unverified
error rather than a clean bill of health. Delayed crash report creation remains
a limitation; continue normal device observation after the bounded check.

Static/runtime mapping requires matching Mach-O UUID and architecture, an
observed module boundary, canonicalized IMP and compatible segment range. A
database is correlated only when its input hash matches the accompanying binary.
Address correlation is evidence of image identity and location, not proof of
source-level behavior, especially for stripped or optimized code.
