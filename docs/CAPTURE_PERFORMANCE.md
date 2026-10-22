# Capture performance, 2026-10-23

Measured on a real iPhone11,8, iOS 16.0, device/host Frida 17.5.0, via the
configured forwarded SSH and Frida connections. Baseline:
`8e6e4f9a16ee2fbf6f7959a2a2a3070e5ad403f6`. The original 3.53-second observation
was one sample; it is not used as a statistical baseline.

## Call chains and counts

| Operation | Before | Vesper |
| --- | --- | --- |
| Ordinary screenshot | list apps → attach/probe → screenshot → detach (4 MCP calls) | `ui_capture(mode="screenshot")` (1 MCP call) |
| Subsequent screenshot | repeats discovery/attach unless caller manually keeps a session | same verified session; no probe/enumeration/attach while valid |
| Five snapshot pages | five full device traversals, then slices | one live traversal, four immutable host-cache reads |
| App test batch | caller orchestrates separate operations | up to 20 UIKit steps + optional final capture in one RPC |

In 20 fresh-process samples, app enumerations fell from 40 to 20; SSH probes and
attachments remained 20 each because every sample starts a new server. Warm
series create one session per setup, with no additional attach/probe/enumeration
for measured consecutive captures. Tests separately cover process changes,
disconnects, cache invalidation, in-flight work and active hook/workflow retention.

## Controlled comparisons

Each row contains 20 successful device samples. Cold and warm comparisons
alternate conditions in chunks of five. p50/p95 use nearest rank; n=20 is a
small tail sample. Warm setup is excluded from timings. Cold samples use a new
MCP process and state directory. Values below are milliseconds, except bytes.

| Condition | MCP calls/sample | Server p50 / p95 | stdio client p50 / p95 | Result bytes p50 |
| --- | ---: | ---: | ---: | ---: |
| Cold, original four-call chain | 4 | 8571 / 10808 | 8705 / 10959 | 2,622,108 |
| Cold, task capture + binary Frida PNG | 1 | 6383 / 7985 | 6495 / 8103 | 2,618,863 |
| Warm, original already-attached screenshot | 1 | 4899 / 5763 | 4949 / 5807 | 2,618,878 |
| Warm, task capture, base64 Frida transport | 1 | 4913 / 5243 | 4947 / 5277 | 2,618,850 |
| Warm, task capture, binary Frida transport | 1 | 4050 / 4442 | 4096 / 4489 | 2,618,849 |
| Five old snapshot pages | 5 | 1365 / 2331 | 1408 / 2378 | 15,984 |
| Five new snapshot pages | 5 | 268 / 301 | 295 / 327 | 5,240 |

Cold startup-to-first-result p50/p95 was 9014/11281 ms before and 6720/8336 ms
after. Server time sums tool handler durations. Client time includes stdio MCP
serialization/transfer; it excludes model scheduling, image vision processing
and viewer display. Those user-visible stages were not instrumented, so these
are not complete agent end-to-end latency claims.

Snapshot totals include first setup in one group (6 calls) and then 5 calls per
group. Device snapshot RPCs were 100 before and 20 after. The new visible-control
summary also has fewer fields than the old full-detail result, so its latency
and size change cannot be attributed solely to pagination. Subsequent pages
were independently checked to execute **zero device RPCs** and return the same
capture timestamp/content despite a later live observation.

## Variability and subsequent checks

The connection disconnected twice during this work. The initial original
four-call run had server p50/p95 3635/3869 ms, while an early new base64 run had
5381/7474 ms. A later identical binary run ranged from roughly 1.2 to 4 seconds.
These differences demonstrate why a single sample or separately timed runs do
not establish a stable speed multiplier. Incomplete/timeout runs are retained
privately and are not counted as successful 20-sample series.

After integrating logs, decryption and debugging, another 20 warm captures
passed: server 3537/4245 ms, stdio 3580/4283 ms, one MCP call each, one session
including setup. Result bytes were 2,318,980 because the displayed UI changed;
that smaller PNG is **not** a same-content compression improvement. The measured
agent hash and summaries are in [capture-benchmarks.json](capture-benchmarks.json).
Later changes to build-marker names do not affect capture code.

The current functional pass also verified native image/local-file identity,
three consecutive screenshots sharing one session, zero-RPC cached pages,
object expiry from 9 retained references to 0, and idle session reclamation.
Selected ivar reads and two-step read-only batches were separately measured at
n=20: server p50/p95 141/182 and 174/193 ms; results 792 and 611 bytes. Their
client measurements used the SDK's in-memory transport, not stdio.

## Feed page scrolling

The installed MCP was measured on Douyin 40.7.0 after rebuilding/installing the
test tweak. `ui_automate` used `scroll`, `pages=1/-1`, `animated=true`,
`settle_ms=500`, and no final capture/text. One cold request selected the Feed
class; 20 warm requests reused its returned view ID and the same Frida session.
They alternated two adjacent cached pages. This is not a 20-new-post network or
content-loading benchmark. No additional attach was needed in the warm series.

| Condition | n | Calls/sample | Server ms | stdio client ms | Result bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| Cold setup + first page | 1 | 1 | 6376.69 | 6423.36 | 537 |
| Warm p50 / p95 | 20 | 1 | 648.87 / 672.75 | 657.74 / 681.90 | 532 / 534 |

Every warm sample reported session reuse. The on-device step itself was
10 / 23 ms p50/p95; server/client time also includes the deliberate 500 ms
settle, main-queue dispatch, RPC and serialization. These stages overlap and
must not be treated as independent additive timing estimates. No image tokens
are required unless the caller requests a screenshot. Model scheduling and
display remain unmeasured. Cold n=1 has no percentile estimate. Earlier timeout
runs were retained privately and excluded from this successful-series summary.
See [per-sample results](scroll-benchmarks.json).

## Encoding and response size

The controlled screenshots were byte-identical lossless PNGs: 828×1792,
1,963,363 bytes, SHA-256
`9a7fa0631da3c9186144bb7b523d26018b2a3db3b0ee1d1755cb70b81578c51e`.
Device base64 payload preparation took median 23 ms versus 1 ms for binary.
Rendering was 167/168 ms and PNG encoding 98/98 ms (binary/base64). RPC total
was 4048/4908 ms and includes device work, marshalling, queueing and forwarded
transport; it is not a pure network measurement. Host save was 1.3/4.5 ms;
native ImageContent construction was about 3–4 ms with normal measurement noise.

Binary Frida transport carries 1,963,363 image bytes instead of a 2,617,820-byte
base64 payload. MCP still uses its native ImageContent encoding, so its roughly
2.62 MB response is largely unchanged. Default resolution, PNG encoding and
quality are preserved. No preview downsampling was added. Viewer display and
model image-token costs were not measured.

Non-image JSON is now returned once in structuredContent, with a brief text
status; `legacy_text_json=true` restores text duplication for clients that need
it. Native images are tested through both the in-memory SDK and real stdio
client, including `ui_capture`, `ui_automate` and the advanced-tool gateway.
Image base64 is never placed in text results or benchmark logs.

The focused catalog advertises 19 tools in 42,343 bytes, versus 70 tools in
129,746 bytes for the full catalog. Advanced schemas load on demand through
`platform_tool`; workflows live in the conditional Agent Skill. Byte counts are
context-size measurements, not tokenizer/model-specific token counts.

## Reproduction

Use the configured phone with the app open, matching Frida client/server, and
the existing verified SSH forward. Keep diagnostic logs/hooks off for timing.

```sh
PYTHONPATH=.venv/frida-17.5.0:src .venv/bin/python scripts/benchmark_matrix.py \
  --config vesper.local.toml --device test --bundle dev.iosdecompiler.fixture \
  --baseline-source /absolute/baseline/src --frida-path .venv/frida-17.5.0 \
  --scenario cold --samples 20 --chunk 5 --output .vesper/benchmarks/cold
```

Repeat with `--scenario reuse`; use `benchmark_capture.py --chain pages` for
pagination and `verify_capture.py` / `verify_runtime.py` for invariants. The
benchmark runner alone can import the historical package for a baseline; Vesper
itself ships no legacy import or CLI aliases. Reports retain counts, timings,
agent hashes and image identity metadata, without pixels or app text.
