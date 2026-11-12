# Check a provider within a durable budget

`keep provider-check [prompt]` makes one diagnostic request with at most 64 output tokens and one HTTP attempt. It reserves projected cost before remote dispatch and settles the reservation from valid reported usage. Missing or malformed usage, a lost response or a provider exception leaves a durable hold across restart. Text can be returned while usage remains uncertain. The command does not automatically retry that call.

Remote admission needs fresh applicable prices and an available allowance. The supported direct DeepSeek route uses the [fresh-price policy](provider-check-pricing.md); other remote diagnostic routes refuse. Credential-free personal local operation remains available.

## Authority and allowance

Personal remote operation requires its captured owner descriptor. Organization operation requires a live session, current roster/role and an admitted provider route. Keep checks authority before reservation and immediately before dispatch. Revocation after reservation retains the hold.

The standalone organization CLI cannot acquire or restore those sessions and refuses the diagnostic. A trusted embedding host can pass an authenticated same-process session through `CliDeps.providerCheckSession` or `KeepApp.providerCheck(prompt, sessionId)`.

The diagnostic uses the `autonomy-subsystem` run, `auto-research` class and `KeepConfig.autonomyBudget`. Defaults are **USD 100 daily**, **USD 50 per run** and **32,000 projected tokens per call**. This command's output cap remains 64 tokens. Consumption and unresolved holds survive restart. Select an authorized allowance explicitly to change these defaults.

## Accounting limits

Input projection uses roughly one token per four prompt characters. Framing, cache-price breakdowns, hidden input and non-token fees remain limitations. Explicit local zero-token fees exclude hosting costs. Injected providers are trusted code and must honor the request contract. See [monetary accounting](monetary-accounting.md) for coverage and bill-reconciliation limits.

## Evidence and history

Source **0.0.6-preview.1** introduced this diagnostic's durable accounting. The prior **0.0.5-preview.1** binary retains its earlier behavior. The **0.0.7-preview.1** [FrontDoor checkpoint](frontdoor-metering.md) extended the ledger to those built-in calls; **0.0.8-preview.1** added the fresh-price admission policy.

The diagnostic's original 170-test receipt covers synthetic endpoints and zero paid calls. It checks reservation before HTTP entry, valid settlement, unknown-price/budget/subject refusal, concurrent admission, revocation and fresh-process unresolved holds. Its source identity and TypeScript/regression results are in [validation evidence](evidence.md). Live organization identity and complete billing enforcement remain open.

The accounting design draws on these primary sources, inspected October 5, 2026:

LiteLLM reserves projected cost and reconciles usage after dispatch:

https://docs.litellm.ai/docs/proxy/users#budget-reservation

Azure API Management distinguishes estimated admission from response-based consumption:

https://learn.microsoft.com/en-us/azure/api-management/llm-token-limit-policy

TigerBeetle distinguishes pending exposure from posted consumption:

https://docs.tigerbeetle.com/coding/two-phase-transfers/

Keep applies those distinctions through its existing `MeteredProvider`, `MeteredGateway` and monetary ledger. Uncertain exposure stays held for inspection.
