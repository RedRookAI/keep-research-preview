# Manual memory-correction monetary admission

MC001 extends MW001's document admission to one manual `POST /memory/correct`. Development source **0.0.10-preview.1** combines these two tickets. The create/correct source checkpoint is being prepared; publication and its exact-source receipt are recorded separately. Downloadable 0.0.5-preview.1 retains its original identity.

## Configure and use

Use the same explicit `KeepConfig.memoryStorePricing` declaration and direct OpenAI text-embedding-3-small descriptor documented for [manual writes](manual-memory-write.md). Pricing is captured operator input with observation time and maximum age; it is not automatically refreshed or signed billing evidence. Query pricing alone does not admit replacement documents. Live memory.write, document processing purpose/region and destination policy must independently admit the operation.

```json
{"id":"existing-note-id","content":"the deploy window is Wednesdays","processing":"configured-provider"}
```

`app.memoryCorrect({id, content}, {processing, sessionId, subject})` backs this endpoint. Remote operation requires explicit configured-provider consent. Inputs and authority options are captured before awaits. The resolved tenant confines the existing note lookup; the replacement retains the original kind, scope and supersedes citation, without accepting caller-directed reassignment. Local personal operation requires no remote consent/price/credentials; injected local memory retains its own encoder. Live organization operation requires same-process session/roster/tenant authority; synthetic local fixtures do not qualify live remote organization custody. Opaque injected remote stores are refused.

## Replacement and accounting

Missing, retired, expired, foreign or unusable original notes do not trigger embedding. Ingestion rejects unsafe replacements before wire. Accepted sanitized text uses the existing bounded document route: one window/attempt, at most 8000 UTF-8 input bytes and 8192 complete JSON bytes. Complete body bytes conservatively project input tokens with no output/cache tokens. This is encoder-specific admission inference, not a universal billing ceiling.

The shared durable monetary ledger reserves before wire and settles matching complete input usage before replacement. Missing/malformed usage, wrong model, HTTP failure or lost acknowledgement retains an unresolved hold across restart; no automatic refund or retry. A known overrun settles actual spend, withholds replacement and blocks further paid admission.

After embedding, live write authority is checked again and the existing complete old-note comparison detects concurrent changes. Reweighting, retirement or a competing correction prevents the stale replacement. Keep preserves the current winning state rather than restoring a stale snapshot. A known charge remains recorded even if permission is revoked, a conflict is found or publication fails. Successful ephemeral publication synchronously retires the old note and inserts one successor with oldId/newId; this is not a new durable disk transaction or replay/idempotency guarantee.

Existing responses remain: 200 with oldId/newId on success; null/404 for missing, rejected or conflicting replacement; 400 for invalid processing; 403 for gateway RBAC denial. Unavailable authority/accounting/publication work returns 409 with a reconciliation message. A 404 alone is not proof that no embedding was billed: a conflict may be detected after known settlement. Reconcile charge and note state before retrying; do not reset a hold.

Other direct corrections, durable custody commands, bulk/system ingestion, consolidation, fitness and task encoders retain their existing behavior. No new persistence backend, billing service, tokenizer, index rebuild or dependencies are introduced.

## Research and evidence

Primary sources checked October 5, 2026: [embedding input/model/usage](https://developers.openai.com/api/reference/resources/embeddings/methods/create), [observed model pricing](https://developers.openai.com/api/docs/models/text-embedding-3-small), [provider data controls](https://developers.openai.com/api/docs/guides/your-data), [conditional concurrent-update prior art](https://www.postgresql.org/docs/current/transaction-iso.html). The update principle supports preserving Keep's existing comparison; PostgreSQL behavior does not qualify Keep's ephemeral backend as a database transaction. Same-day MW001/ME001 findings are reused where unchanged.

The focused correction/create/query/memory/transport/gateway profile passed 153 tests, zero failures/skips, including 31 correction cases. Actual owned loopback sinks and fresh child processes use synthetic replies/keys; no paid vendor operation. Final versioned private/public source qualification is recorded at the combined checkpoint. Full native, live organization custody and downloadable artifact qualification remain separate.
