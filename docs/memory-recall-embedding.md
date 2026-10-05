# Memory-recall query monetary admission — October 5, 2026

Development source **0.0.9-preview.1** adds monetary admission to the built-in ordinary memory store's query embedding. It reuses the private durable autonomy monetary ledger and existing governed bounded transport. It does not rebuild an index or meter document ingestion, fitness, task encoders or opaque injected stores. Downloadable **0.0.5-preview.1** retains its original contents and qualification.

## Research and configured route

Primary sources checked October 5, 2026: [OpenAI embedding API](https://developers.openai.com/api/reference/resources/embeddings/methods/create), [model pricing](https://developers.openai.com/api/docs/models/text-embedding-3-small), [encoding guide](https://developers.openai.com/api/docs/guides/embeddings), and [LiteLLM reservation prior art](https://docs.litellm.ai/docs/proxy/users#budget-reservation). The observed standard price was USD **0.02 per million input tokens**. Direct embeddings return a model and prompt/total usage. Reserve-before-processing and settlement already exist in Keep, so this change adds a consumer rather than another billing service.

Only the captured `openai-compatible` descriptor with base URL `https://api.openai.com` and model `text-embedding-3-small` is admitted; aggregator routing is excluded. That descriptor is the existing model route. Keep does not infer a separate encoder from a chat model or migrate stored vectors. Stored and query vectors must use the same representation; configuring an embedding-only model does not make it a chat model.

The programmable host explicitly supplies `KeepConfig.memoryRecallPricing`:

```ts
memoryRecallPricing: {
  inputPerMillion: 0.02,            // operator-verified current USD input rate
  observedAtMs: priceObservation.observedAtMs,
  maxAgeMs: operatorPolicy.maxAgeMs,
}
```

`priceObservation` and `operatorPolicy` are host-owned inputs; this snippet is not a standalone command. Record the actual price observation timestamp, not the request time or a fabricated revalidation. Rates must be positive finite numbers, observation timestamps nonnegative safe integers, and maximum age a positive safe integer. Fields are captured at composition. Future-dated, expired or missing observations and unsupported routes refuse before reservation/dispatch. This is a **trusted operator price declaration**, not an automatically refreshed or signed provider quote. Recheck the official source and supply a newly observed declaration when expired. No new CLI environment flags or background fetcher are introduced.

The host must separately configure the existing query/document `embeddingProcessing` purposes/regions, residency allowlists and monetary `autonomyBudget`. Organization descriptors retain their own installed-release admission. Price/budget configuration grants no egress or human authority.

## Admission and accounting

`MemoryStore.retrieve` uses a query-only gateway hook. Personal built-in local recall stays credential-free and incurs no declared token fee. Remote queries require `memory.read`, current route/pricing and existing privacy/egress admission. One query window, at most 65,000 raw UTF-8 bytes and 65,536 complete serialized JSON bytes is admitted, with exactly one HTTP attempt. Serialization overhead counts in the reserve; oversized escaped text refuses rather than splitting or retrying it.

The pre-call projection uses complete serialized UTF-8 JSON bytes as input tokens at the configured rate, with zero output/cache tokens. This is deliberately conservative for the selected byte-level cl100k_base representation; it is an inference, not an exact tokenizer or provider-certified account ceiling. The existing envelope's per-call token ceiling governs **output**, so a zero output ceiling can admit input-only embeddings. Input is bounded by the query transport and money caps.

The reservation is durable before wire and shares the autonomy envelope/lock with provider-check and built-in FrontDoor. This is the internal metering ledger, not the separate exported scheduler ledger. Missing, negative, inconsistent or wrong-model usage and uncertain entered failures retain the hold. Valid matching nonnegative integer prompt/total counters settle input spend against the reservation's captured rates. A known usage overrun records actual spend, then withholds the result and blocks further paid admission under that envelope. Neither a 503 nor a lost acknowledgement causes an automatic retry or release of uncertain monetary exposure. Restart does not reset holds or grants.

The query hook preserves indexing/document calls as separate paths. Opaque injected memory stores cannot be metered by the composed recall capability and are refused remotely; independently constructed gateways/stores remain outside this claim. Wider encoder configuration and document billing require separate tickets.

## Session and HTTP consumer

`app.memoryRecall(query, { sessionId, subject, agentId })` returns the existing `{ id, content, kind, importance }` hits. `GET /memory` carries the authenticated `x-keep-session` and resolved tenant into that capability. Organization recall requires a live same-process session, current human roster/role, `memory.read`, matching tenant and any admitted deployment tenant. It rechecks authority after reservation and immediately before wire; there is no organization owner fallback. Tenant recall uses the existing project-only candidate set.

Local personal/injected-resolver HTTP behavior retains the gateway's existing RBAC and tenant selection. Synthetic local session evidence is not qualification of a live organization issuer, separately admitted paid organization encoder or independent custody. Refused/unavailable HTTP recall returns **409** without raw provider details and tells the caller to preserve pending accounting. Resolve admission or reconcile uncertain work before retrying; do not reset state merely to clear a hold.

## Qualification boundary

[Source qualification receipt](qualification/memory-recall-embedding-2026-10-05.json) records the exact tested source, relevant tests, failed development attempts and controls. Actual loopback HTTP sinks and fresh child processes exercise dispatch/accounting; API keys and replies are synthetic, with zero paid requests. Existing encoding/privacy/transport/session/budget and earlier diagnostic/FrontDoor regressions are checked separately from live vendor operation. Full native, paid-provider, live organization custody and downloadable artifact qualification are not established by this source checkpoint.
