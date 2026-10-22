# iOS Decompiler MCP implementation plan

Implemented in this order. See [validation and limitations](VALIDATION.md) for
executed checks and the physical-device work that remains unverified.

1. Foundation: official MCP Python SDK, typed configuration/results, fail-closed
   permissions, persistent registry, bounded jobs, AsyncSSH and Frida adapters.
   Prove tool discovery/invocation over stdio with mocked infrastructure.
2. Inspection: ship a Frida 17-compatible Objective-C bridge agent; implement
   bounded UIKit and Objective-C runtime queries with session-scoped identities.
3. Tweak development: generate editable Theos projects, validate runtime signatures,
   build/package, approval-gated deployment, evidence-based verification and rollback.
   Add a deterministic UIKit fixture and a runnable device demonstration.
4. Advanced analysis: bounded tracing and an optional isolated IDA headless worker;
   correlate runtime addresses only with matching Mach-O identity and segment evidence.
5. Hardening: exercise failure paths, cancellation, redaction and approvals; run
   lint/type/integration checks; document setup, clients, limitations and hardware steps.

Tests use fakes only at external boundaries. Hardware, Theos and IDA execution are
reported separately from mocked tests. No real device changes without approval.
