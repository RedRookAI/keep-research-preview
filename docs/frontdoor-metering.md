# Budget-bound FrontDoor calls — October 5, 2026

Development source **0.0.7-preview.1** routes built-in FrontDoor model calls through
Keep's existing durable monetary ledger. It also makes the existing paste-summary
flow reachable through validated `/message` attachment metadata. The downloadable
0.0.5-preview.1 binary retains its original contents and qualification.

## Research and smallest change

Primary sources retrieved October 5, 2026:

- [LiteLLM reservation](https://docs.litellm.ai/docs/proxy/users#budget-reservation) reserves estimated exposure before processing and reconciles actual consumption afterward. Keep already has this machinery; no new proxy or dependency is needed.
- [Node async context](https://nodejs.org/api/async_context.html#asynclocalstoragerunstore-callback-args) confines `run` context to its callback and asynchronous descendants. `enterWith` can persist across other synchronous handlers. Use existing `run`/`getStore`, available since Node 12/13 and exercised here on pinned Node 22.23.2; newer Node 26 APIs are not required.
- [TigerBeetle two-phase transfers](https://docs.tigerbeetle.com/coding/two-phase-transfers/) separate pending exposure from posted consumption. Its automatic transfer expiry is not evidence that an external model request was free; Keep retains ambiguous exposure.

Source inspection found two concrete gaps: the shared FrontDoor callback used the
plain gateway, and `/message` discarded existing attachment flags. A tenant label
was passed to a cached FrontDoor without a live session. Reuse monetary admission
and carry each message's authority separately; do not cache sessions on tenant objects.

## Use and behavior

The existing gateway accepts pasted project/file content with optional metadata:

```json
{"message":"Project notes: a tiny task queue.","hasAttachments":true,"attachmentCount":1}
```

Send this to `POST /message` with the configured gateway authorization. Organization
requests also need their authenticated `x-keep-session` header. `hasAttachments` must
be boolean; `attachmentCount` must be a nonnegative safe integer. This metadata routes
the message's pasted text into existing sanitization/chunking; it does not upload,
read or extract an external file, and adds no file-upload GUI. Body tenant/session
labels cannot authorize spending.

Built-in model calls require an admitted route, acceptable configured prices and
remaining durable allowance. Each call reserves before dispatch, retains its explicit
output bound (256 tokens for summarization) and uses one transport attempt. Every
valid chunk gets its own reservation. Valid reported usage settles the matching
reservation. Missing/malformed usage, lost response or entered provider exception
retains a hold across restart. A refused/uncertain call stops further built-in model
calls in that gateway message; remaining work uses sanitized deterministic fallback.
A useful fallback response does not prove that an earlier model call was free.

Personal local operation remains credential-free. Organization model entry requires
a live same-process session, current admitted human roster/role, matching tenant,
selected organization route and `review.view` permission. These are checked before
reservation and again before provider entry. Provider-check retains its separate
`change.solve` permission and 64-output bound. Two concurrent sessions, including
sessions for the same tenant, cannot lend model authority to one another.

Library hosts should use `KeepApp.frontDoorMessage(message, options)` with the live
session and resolved tenant. Direct organization FrontDoor calls without that request
context fall back. Direct personal `.handle` retains per-call metering; the message
failure latch belongs to `frontDoorMessage`. Existing conversation state remains
cached by tenant; this change does not provide per-human conversation isolation.

## Coverage and limits

The shared built-in callback also serves guided reasoning, safety review and setup;
this checkpoint exercises the gateway summary consumer and relevant regressions.
An optional injected custom brain is trusted code outside the built-in coverage.
Ordinary embeddings and other direct library calls remain separate obligations.

FrontDoor shares the existing `autonomy-subsystem` run, `auto-research` class and
`KeepConfig.autonomyBudget` with other metered work. Existing grants, consumption,
revocation and holds survive reconstruction. This is a shared process/state allowance,
not newly implemented fleet or per-tenant billing aggregation. Rates remain dated
configured seed/last-good inputs; approximate input projection, cache/framing and
non-token charges prevent a universal bill guarantee. See [monetary accounting](monetary-accounting.md).

[Evidence](evidence.md) records the exact source and relevant profile. Fixtures use
actual loopback provider HTTP plus synthetic organization sessions/rosters and an
injected local provider. Zero paid model calls; no live IdP, independent custody,
newly qualified remote enterprise path, full/native build or new archive qualification.

Future tickets must research current prior art and actual consumers, implement their
smallest authorized scope and vet useful/refused/recovery outcomes before completion.
This checkpoint activates no subsequent implementation batch.
