# Fresh prices for provider-check — October 5, 2026

Source checkpoint **0.0.8-preview.1** requires fresh attributable prices for the one supported remote diagnostic route: OpenAI-compatible `deepseek-flash` at `https://api.deepseek.com` or `/v1`. Other remote routes, legacy aliases and aggregator routing refuse this diagnostic before model transport. This source change does not update the downloadable 0.0.5-preview.1 binary. Credential-free built-in local operation remains supported.

## Research and decision

Primary sources inspected October 5, 2026:

- [DeepSeek official prices](https://api-docs.deepseek.com/quick_start/pricing/) identify the direct endpoint and distinguish peak/off-peak and cached/uncached tokens. The observed peak uncached input/output prices are USD 0.30/1.20 per million tokens. Keep parses the supported current table and uses peak rates at every hour; it does not guess holidays, use retired aliases or promise an exact invoice. Layout/model/tier changes refuse instead of guessing.
- [HTTP caching, RFC 9111 section 4.2.3](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2.3) defines age from Date, Age and response delay. Keep conservatively accounts for these plus time since receipt. Fetching an old cached page does not reset its age. Last-Modified describes publication history rather than new verification.
- [LiteLLM reservation](https://docs.litellm.ai/docs/proxy/users#budget-reservation) supports reserving projected exposure before provider processing. Keep reuses its existing durable monetary ledger and reference container; no dependency, database or service was added.

The ordinary reference seed and last-good presentation behavior remain unchanged. This diagnostic has a separate attributable price category within the existing registry. Refresh happens only on an authorized diagnostic when evidence is absent or expired. Failed refresh preserves historical evidence but cannot authorize a stale call. Concurrent initial refresh is single-flight; a caller that finds the refresh still in progress may refuse and should wait for its result before a deliberate new diagnostic. No automatic model retry occurs.

## Explicit policy and authority

Choose a maximum age in milliseconds. For example, an owner who accepts one-day-old published rates can add this to an already configured direct DeepSeek route:

```sh
KEEP_PROVIDER_CHECK_PRICE_MAX_AGE_MS=86400000 keep provider-check 'brief diagnostic'
```

The example assumes `KEEP_PROVIDER=openai-compatible`, `KEEP_PROVIDER_AUTHORITY=owner`, the supported base URL/model, an existing credential and remote-processing declaration. The maximum age must be a positive safe integer; there is no implicit age policy for a remote diagnostic. Personal local mode needs no price policy and rejects remote-only configuration.

An explicit owner CLI policy permits the fixed public metadata host `api-docs.deepseek.com` in its existing owner egress policy. A trusted embedding host supplies `KeepConfig.providerCheckPricing: { maxAgeMs }` and must separately allow that host in its existing residency policy. Air-gap always refuses metadata egress. Organization policy is never widened: it needs its own allowlist permission plus the existing admitted provider and live same-process session. The standalone organization CLI still lacks session acquisition and refuses before metadata retrieval.

The metadata request is one fixed public GET without model credentials, cookies or prompt data, refuses redirects, and has a five-second deadline and 512 KiB body bound. Unsupported response status/type, missing or invalid Date/Age, future source clocks, unsupported schemas and expired evidence cannot authorize provider dispatch. A source digest, observed/effective verification times, selected rates and configured maximum age accompany the local price-selection audit record.

## Durable admission and limits

Each diagnostic captures one immutable quote for its shared monetary ledger reservation. The ledger records those rates and uses them for matching usage settlement even if a later call refreshes prices. It retains the existing 64-output-token bound, one model transport attempt, durable pending exposure and live authority recheck. Quote expiry or replacement while awaiting reservation refuses provider entry and conservatively keeps that hold; it does not invent a refund. Restart fetches pricing again and preserves earlier exposure.

This freshness policy applies only to `provider-check`. Built-in FrontDoor and unattended routes retain their previous configured-price behavior; ordinary embeddings remain a separate obligation. The public official page is attributable evidence observed under the operator's age policy, not a signed quote or guarantee that a provider cannot change prices during that interval. Peak rates conservatively cover the parsed token tiers; prompt framing, approximate input projection, hidden tokens, non-token fees and exact bill reconciliation remain open.

## Vetting scope

Acceptance exercises synthetic metadata and real owned loopback model HTTP, durable reserve-before-wire, rate refresh, no dispatch on refused evidence, expiry during reservation, immutable concurrent quotes, existing uncertain holds across fresh processes, runtime policy capture and the actual CLI consumer. Actual primary-source HTML parsing is checked separately against the October 5 observation; no paid model request is required. Relevant source tests and their exact source/version identity are recorded in [evidence](evidence.md). This does not qualify a new archive, live IdP, independent custody or a universal billing ceiling.

Every subsequent ticket must research current prior art and actual consumers, implement the smallest authorized change, and vet useful/refused/recovery outcomes before completion. No next implementation goal is activated by this checkpoint.
