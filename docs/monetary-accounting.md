# Monetary accounting on metered model calls

The 0.0.10-preview.1 development checkpoint adds [manual document writes](manual-memory-write.md) and [manual corrections](manual-memory-correction.md) to the shared monetary ledger. Combined exact-source qualification and publication are recorded separately. Earlier receipts retain their original source coverage; other document/task/fitness consumers remain outside this change.

This describes the corrected development implementation. It does not change the
results or contents of the historical research-preview release.

`MeteredProvider` and `MeteredGateway.generateMetered` reserve projected token cost
before entering the provider. Outstanding reservations count against the run and
admission day's allowance. Valid returned usage settles the matching reservation;
exceptions after entry and incomplete or invalid usage leave the reservation open.
A received usage overrun is recorded and stops further paid admission under that
envelope. It cannot undo a cost already incurred.

The request has one explicit output limit (512 when omitted by `MeteredProvider`).
The built-in HTTP transport and brokered path preserve that limit and enforce one
HTTP attempt on metered calls. Ordinary, unmetered HTTP calls retain their configured
retry policy. An injected provider is trusted code and must honor the request contract;
an optional request field cannot constrain an arbitrary implementation.

## Estimates and coverage

Input projection is approximately one token per four prompt characters. It is not
a provider-certified bound and does not cover hidden input, framing or all tokenizer
behavior. Token rates are configured inputs, not independently verified bills.
The generic result currently reports aggregate input tokens; settlement prices those
as fresh input, without a complete cache-price breakdown. Tool fees, hosting, model
training and other non-token charges are not reserved by this route.

Unknown remote pricing refuses admission. The composed remote route uses its captured
configured model identity rather than its wrapper's display name to look up prices.
The built-in offline fixture and explicitly sacrificial local development configuration
have zero token fees in composition; this does not measure hosting costs or attest
that arbitrary injected development code is network-free.

The October 5 development source meters `provider-check` and built-in FrontDoor
model calls through this ledger. [One ordinary memory-recall query route](memory-recall-embedding.md) now also uses it under an explicit dated price declaration. Manual POST /memory and POST /memory/correct document embeddings also use it under explicit document consent/pricing/write authority. Other direct interactive calls and other document/task/fitness embeddings remain outside this monetary coverage. Bounded embedding work has a separate request/byte/window budget. The velocity
breaker measures rate after calls; its post-call error does not establish non-execution.
These distinctions are why Keep does not advertise a universal spending ceiling.

Direct HTTP streaming distinguishes missing or malformed usage from explicitly
reported zero counters. Useful text can still be returned with `usageComplete:false`;
a consumer using monetary settlement must retain that uncertainty. OpenAI-compatible
streams may omit the final usage chunk, and Anthropic output snapshots are cumulative,
not separate amounts to add. Enabling or qualifying a provider's usage-reporting option
remains route-specific; these checks cannot make a provider report consumption.
The default metered wrapper uses nonstream generation. Custom stream adapters must
preserve the returned completeness flag. `HttpProvider.lastUsage` is a shared
diagnostic of the last parsed response, not per-request billing evidence.

## Persistence and API use

Ledger mutations are asynchronous and must be awaited: `grant`, `revoke`, `beginRun`,
`reserve`, `settle`, `recordSpend` and `voidBeforeDispatch`. They require a durable
Spine and its configured shared locking domain. Separate processes require the actual
shared filesystem lock, not separate in-process mutexes. Never run old and corrected
accounting writers concurrently on the same state.

Reporting getters expose the last loaded view; await `refresh()` before a diagnostic
read that needs current durable state. A diagnostic check is not a reservation.
Only reservation performs atomic accounting admission. The separate SafetyRail
approval/soft-cap check is not a replacement for metered dispatch.

Repeating a grant or run identity does not reset consumption. Composed startup does
not revive a revoked envelope. A configuration that differs from existing durable
authority requires an explicit grant revision, preserving the earlier consumption.
Legacy preview records do not contain complete monetary consumption. The corrected
ledger will not fabricate it as zero: paid work under an old allowance remains held.
An owner can deliberately authorize a distinct allowance; changing a run ID alone
does not clear the envelope's unknown history. Existing history is retained.

Only known non-entry permits voiding a reservation. Do not use `voidBeforeDispatch`
to clear an ambiguous provider exception. The current API does not provide general
provider-bill reconciliation or automatic expiry/refund of unresolved reservations.

## October 5 provider-check scope

The diagnostic requests 64 output tokens with one attempt. It shares the existing
`autonomy-subsystem` run and `auto-research` class, including consumption, revocation
and unresolved holds. Configure `KeepConfig.autonomyBudget` to authorize a different
allowance; existing durable grants do not reset on startup. The default envelope
is USD 100 daily, USD 50 per run and 32,000 projected tokens per call. The diagnostic
still limits output to 64. These are configured admission caps, not verified bills.

Organization operation needs a live same-process session, current roster/role and
the admitted provider route. Authority is rechecked after reservation before entry.
The standalone organization CLI has no session acquisition and therefore refuses.
Personal local mode remains credential-free; remote owner mode requires its captured
owner route. The later [fresh-price checkpoint](provider-check-pricing.md) requires
fresh attributable rates and an explicit maximum age for the supported direct
DeepSeek diagnostic; other remote diagnostic routes refuse. It preserves rates
on each durable reservation and does not widen FrontDoor pricing qualification.
See [research, acceptance and limits](provider-check.md).

## FrontDoor request scope

The [FrontDoor source checkpoint](frontdoor-metering.md) scopes the gateway message's
resolved tenant and header session with per-app async context. Every built-in call
reserves through the same internal monetary ledger; file/paste summarization retains
its 256-output-token bound and one transport attempt. Session/current roster/role,
bound tenant, provider route and `review.view` permission are checked before
reservation and again before provider entry. Cached tenant instances retain no session.

Each valid chunk gets a separate reservation. Refusal or uncertain consumption stops
further built-in model calls in that message and preserves deterministic fallback;
outstanding exposure survives restart without automatic expiry/refund/replay.
`frontDoorMessage` supplies this message-level behavior. Ordinary embeddings, optional
injected custom brains, other direct library routes, fresh-rate verification and
fleet/per-tenant budget aggregation remain separate obligations. The allowance is the
existing shared process/state envelope, with its previously documented defaults.
