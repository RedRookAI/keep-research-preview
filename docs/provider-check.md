# Budget-bound provider-check — October 5, 2026

The **0.0.6-preview.1** source checkpoint meters this one diagnostic through Keep's
existing durable monetary ledger. It does not add this behavior to the previously
published 0.0.5-preview.1 binary. Other interactive and ordinary embedding routes
remain separate obligations.

The later **0.0.7-preview.1** [FrontDoor checkpoint](frontdoor-metering.md) extends
the same ledger to built-in FrontDoor calls. Its source has separate qualification;
this diagnostic's original 170-test receipt retains its original source identity.

The **0.0.8-preview.1** [fresh-price checkpoint](provider-check-pricing.md) now
requires an explicit maximum-age policy and a fresh official observation for the
one supported direct DeepSeek route. Other remote diagnostic routes refuse.
The older qualification below remains source-bound; local operation is preserved.

## Research before implementation

Primary sources inspected October 5, 2026:

- [LiteLLM budget reservation](https://docs.litellm.ai/docs/proxy/users#budget-reservation) reserves projected cost before dispatch and reconciles actual cost afterward. Stale or unavailable accounting needs fail-closed admission; missing prices differ from explicit zero fees.
- [Azure API Management token limits](https://learn.microsoft.com/en-us/azure/api-management/llm-token-limit-policy) distinguish estimated admission from response-based consumption. Concurrent requests can overshoot response-only accounting.
- [TigerBeetle two-phase transfers](https://docs.tigerbeetle.com/coding/two-phase-transfers/) distinguish pending exposure from posted consumption. Transfer expiry cannot prove that an external model request incurred no cost.

Decision: reuse `MeteredProvider`, `MeteredGateway` and the existing internal
monetary ledger. No new service, dependency or accounting framework. Preserve
ambiguous exposure rather than automatically expiring or retrying it.

## Behavior and authority

`keep provider-check [prompt]` requests at most 64 output tokens and one HTTP attempt.
Fresh applicable prices under the explicit supported-source policy and an
acceptable durable allowance are required before remote dispatch. Awaited reservation precedes the actual provider request; valid
reported usage settles that reservation. Missing/malformed usage, a lost response
or an entered provider exception leaves a durable hold across process restart.
The command can return useful text while usage remains uncertain; successful text
is not evidence of settlement. It never automatically retries an ambiguous call.

Credential-free personal local operation remains supported. A remote personal
route needs its captured owner descriptor. Organization operation requires a live
session, current roster/role and the admitted organization provider route. Checks
run before reservation and immediately before provider entry. A revoked or changed
subject cannot borrow owner authority; revocation after reservation conservatively
retains that hold.

The standalone organization CLI does not yet acquire or restore authenticated
sessions and therefore refuses this diagnostic. A trusted embedding host can pass
an already authenticated same-process session through `CliDeps.providerCheckSession`
or `KeepApp.providerCheck(prompt, sessionId)`. A gateway bearer token is not that
session. Synthetic organization fixtures do not qualify live IdP or custody.

The diagnostic shares the existing `autonomy-subsystem` run, `auto-research` class
and `KeepConfig.autonomyBudget`. Consumption, revocation and holds are preserved;
startup does not reset the allowance. Defaults are USD 100 daily, USD 50 per run and
32,000 projected tokens per call; output remains capped at 64 for this command.
Use an explicit authorized envelope for a different allowance.

## Limits and acceptance

Current remote diagnostic admission uses the fresh official observation described
in [price policy](provider-check-pricing.md); other routes retain their configured
seed/last-good inputs. Neither establishes verified provider bills.
Input projection is approximately one token per four prompt characters. Framing,
cache price breakdowns, hidden input and non-token fees remain limitations.
Local zero token fees do not measure hosting costs. Custom injected providers are
trusted code and must honor the request contract. See [monetary accounting](monetary-accounting.md).

Acceptance covers useful local operation, actual loopback HTTP reservation before
wire, valid usage settlement, unknown-price/budget/subject refusal, concurrent
admission, revocation before entry and fresh-process unresolved holds. All model
endpoints are synthetic: zero paid provider calls. The development checkpoint is
qualified only by the relevant TypeScript and outcome/regression profile recorded
in [evidence](evidence.md). No new native build, installable archive, independent
audit, real organization custody or universal billing ceiling is claimed.

Every subsequent ticket must research current prior art and actual consumers,
implement the smallest authorized scope, then vet useful/refused/recovery outcomes
before candidacy or completion. No subsequent implementation batch is activated here.
