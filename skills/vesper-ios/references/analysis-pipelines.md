# Compose analysis tools

Choose an evidence chain based on what is missing, rather than dumping the
entire app and loading everything for every question.

| Question | Pipeline |
| --- | --- |
| Declared ivars, properties, method signatures offline | `app_decrypt` → `objc_dump(binary_path=…, class_name=…)` using classdumpc |
| Function logic, branches, callers or data references | `app_decrypt` → `ida_open_binary` → bounded symbols/xrefs/disassembly → selected Hex-Rays pseudocode |
| Which live method implements a selector? | Runtime method IMP → `ida_resolve_runtime_address` against the matching decrypted image |
| Current ivar values or view ownership | `objc_query_instances` with known handles/fields; UI detail only for the selected control |
| Behavior while a button is pressed | Cursor-filtered logs or one bounded trace → `ui_automate` → assertion → stop instrumentation |

## Decrypt exactly the required image

Use `app_decrypt(action="modules")` once when the relevant module is unknown.
Many apps keep most code in an app framework: dumping only the launcher does
not recover that framework's code. Select its observed `module_name` or exact
`module_path`; Vesper only dumps already-loaded app images and does not force
framework initialization. A new process/version requires fresh evidence.

Dump starts a background job by default. Wait on `job_status` with reasonable
backoff instead of tight polling. The completed result supplies `binary_path`,
SHA-256, architecture, UUID and checked zero encryption IDs. Do not call a
file decrypted just because the transfer or patch operation returned success.
Cancelled/failed operations clean their own remote temporary file and incomplete
local transfer. A completed local binary is retained for subsequent analysis.

## Decrypt → classdumpc

Call `objc_dump(binary_path=result.binary_path, class_name="ObservedClass")`.
No additional device attach is needed. Headers are local artifacts; opt into
a bounded preview or read only the relevant declarations. An unchanged static
query reuses the bounded 5-minute header cache. Static declarations do not prove
the current value of an instance; return to `objc_query_instances` for that.

## Decrypt → IDA/Hex-Rays → runtime

Load the `ida_open_binary` schema with `platform_tool`, then open `binary_path`
once. Keep the resulting `ida_session_id` while searching symbols and xrefs.
Decompile a selected function, page only when needed, then close the worker.
Hex-Rays requires an installed license for the architecture. Missing IDA is a
component requirement to report, not evidence of a decryption failure.

For a live selector, pass `device_id`, `session_id`, `class_name`, `selector`,
and `ida_session_id` to `ida_resolve_runtime_address`. It checks image UUID,
architecture, database input identity, image bounds and slide/PAC handling.
Do not correlate by a stale address or a class name alone. Pseudocode is inferred
logic; a matching IMP address still needs a live action/trace to prove behavior.

Preserve the original app's private binaries and headers locally. Return a
small evidence set and paths, rather than putting entire dumps into the model.
