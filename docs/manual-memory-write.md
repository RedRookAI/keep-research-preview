# Manual memory-write monetary admission

Development source **0.0.10-preview.1** combines MW001 manual writes and [MC001 manual corrections](manual-memory-correction.md) for the next public checkpoint. MW001 was previously vetted and privately saved at metadata 0.0.9-preview.1; its private receipt keeps that exact identity. The earlier public ME001 receipt qualifies query code at its own revision. The new combined export receives a separate qualification; downloadable 0.0.5-preview.1 retains its original identity.

## Scope and host configuration

One manual `POST /memory` write can use the existing direct OpenAI text-embedding-3-small descriptor, with separate `KeepConfig.memoryStorePricing`: positive finite USD `inputPerMillion`, nonnegative integer `observedAtMs`, and positive integer `maxAgeMs`. The fields are captured at composition. No document price is inferred from memoryRecallPricing. Missing/future/expired document price refuses remote write admission. This is an operator-declared price observation, not automatically refreshed metadata or provider-signed billing evidence.

Research checked October 5, 2026: [API input/usage contract](https://developers.openai.com/api/reference/resources/embeddings/methods/create), [model pricing](https://developers.openai.com/api/docs/models/text-embedding-3-small), [data controls](https://developers.openai.com/api/docs/guides/your-data). Same-day ME001 representation and reserve-before-wire research is reused where unchanged. The public model page lists standard USD 0.02/million input tokens; confirm and record the actual observation time before supplying a declaration. Provider retention/account controls remain separate; a host declaration or budget is not proof of zero retention or regional processing.

Remote manual writes explicitly include:

```json
{"content":"the deploy window is Tuesdays","processing":"configured-provider"}
```

The host must independently admit the existing document processing purpose/region and destination through embeddingProcessing/residency. Query purpose, memory.read and an available budget grant no document or memory.write authority. The selected descriptor remains the existing primary route; no chat-to-encoder inference, separate encoder rollout, vector migration or index rebuild is introduced. Stored and query vectors must use the same representation.

Local personal operation needs no price, credentials or remote processing consent. Personal local tenant views retain the gateway's existing RBAC/filtering; live organization operation requires the composed same-process session/roster/tenant/write permission and any existing installed-release admission. Opaque injected remote memory stores are refused by this capability. Injected local stores keep their own embedding representation and remain outside monetary/locality claims for the built-in remote path.

## Accounting and publication

`app.memoryStore(args, { processing, sessionId, subject })` backs this single manual endpoint. Operation args/consent and scope are captured before awaits. Existing ingestion sanitization still precedes the embedding; the exact sanitized note is bound to its returned vector. A trusted per-operation embedding callback and publication-authority check also serve the manual correction endpoint; bulk/system ingestion, durable custody commands, consolidation, fitness and task encoders retain their existing behavior.

One document window, at most 8000 raw UTF-8 bytes and 8192 complete serialized JSON bytes, and one HTTP attempt are admitted. Oversized/escaped text refuses instead of being chunked. Complete body bytes are conservatively projected as input tokens at the selected input rate, with zero output/cache tokens. This byte-based inference fits the selected 8192-token model input limit without installing a tokenizer; it is not a universal provider-certified charge ceiling. The existing envelope's output ceiling meaning is unchanged.

Use the existing internal durable autonomy monetary ledger/envelope/lock domain shared with query recall, diagnostics and built-in FrontDoor. Reserve precedes wire. Matching complete prompt/total input usage settles captured rates; malformed/missing usage, wrong model, HTTP failure or lost acknowledgement retains an unresolved monetary hold. Restart or a retry does not clear that exposure. Known usage overrun records actual spend, withholds the lesson and stops further paid admission.

Publication is a separate outcome: valid embedding usage is settled before the existing synchronous lesson publication. Live write authority is checked before entry and again before publication. If authority or publication fails after known settlement, the actual charge remains; no new lesson is acknowledged and no refund is fabricated. HTTP returns 409 with a reconciliation message on unavailable/uncertain work, 400 for invalid processing choice, 422 for ingestion rejection, and existing 403 for RBAC denial. Do not blindly replay a 409 or reset state to clear a hold; inspect charge and possible publication state separately.

This endpoint still uses the existing ephemeral ordinary MemoryStore. Its successful HTTP response is not a newly qualified disk transaction or durable custody journal. No automatic replay/deduplication claim, new persistence infrastructure, billing service or full-index work is added.

## Evidence boundary

Vetting uses synthetic keys/replies, actual owned loopback HTTP sinks and fresh child processes; paid vendor operation, live organization encoder/custody, full native and new downloadable artifact qualification remain separate. [Private source receipt](qualification/manual-memory-write-2026-10-05.json): emitting typecheck, 690 tests in 43 files (zero failures/skips), plus 24 synthetic recovery checks passed at the exact recorded private revision. Public export and qualification must occur on the combined batch and version selected for the next public checkpoint.
