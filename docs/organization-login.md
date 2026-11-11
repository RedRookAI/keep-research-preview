# Organization browser login prototype

Current source adds an optional, single-issuer authorization-code login with S256 PKCE. A rostered user receives an opaque server-side session bound to the configured tenant. The existing assertion fixtures remain available when code-flow configuration is absent. Personal owner mode keeps its existing token and console behavior and makes no identity-provider requests.

This addition has local RSA, transport and gateway fixtures. An actual organization issuer, registered client/callback, approved roster and credential-custody arrangement have not been supplied. Live login and installed enterprise qualification remain open. The existing personal preview qualification applies to its recorded artifact and scope.

## Configure the existing organization profile

Keep still requires the organization's existing provider, release-admission, tenant, JWKS, principal roster, delegation and residency references. Add an optional `login` object inside that provider profile's `organization` object. The profile saves a client-secret **file reference**; the secret value belongs in the selected private file.

Replace each uppercase metadata value below with the exact approved client or HTTPS endpoint. `publicOrigin` is the external origin without a trailing slash; `redirectUri` is that origin followed by `/auth/oidc/callback`. The example numeric policy values are explicit configuration choices to review for the deployment.

```json
{
  "clientId": "REGISTERED_CLIENT_ID",
  "authorizationEndpoint": "APPROVED_HTTPS_AUTHORIZATION_ENDPOINT",
  "tokenEndpoint": "APPROVED_HTTPS_TOKEN_ENDPOINT",
  "jwksUri": "APPROVED_HTTPS_JWKS_ENDPOINT",
  "publicOrigin": "APPROVED_HTTPS_KEEP_ORIGIN",
  "redirectUri": "EXACT_REGISTERED_HTTPS_CALLBACK",
  "clientSecretFile": "/absolute/private/client-secret",
  "transactionTtlMs": 300000,
  "maxTransactions": 100,
  "requestTimeoutMs": 10000,
  "maxResponseBytes": 65536,
  "leewaySec": 60,
  "sessionIdleMs": 1800000,
  "sessionAbsoluteMs": 28800000,
  "maxSessions": 10000
}
```

The existing `keep provider configure` command accepts `--identity-login='<complete JSON object>'` alongside its ordinary organization options. Direct environment setup uses `KEEP_IDENTITY_LOGIN_JSON` with that same complete object and explicit organization provider authority. An incomplete or invalid configuration refuses; it cannot select personal owner access. No operational policy field is optional in this profile. Endpoints must be exact HTTPS URLs without embedded credentials, query or fragment. Client ID must equal `KEEP_IDENTITY_AUDIENCE` in this restricted profile. Preserve the issuer string exactly, including a trailing slash if the issuer declares one.

The selected client-secret file must be a readable, single-link regular file owned by the runtime user, mode 0600 or stricter. The runtime opens the final component without following a symlink and checks the opened descriptor before reading. Store the UTF-8 value with no embedded control characters; one final newline is allowed. Keep reads it only for token exchange and does not save it in the session or profile. These are trusted-host protections; the same process sees the credential during exchange. Independent or native custody remains separate work.

Roster entries map an opaque issuer subject to one unique Keep principal ID, role and the configured tenant. Email, role and tenant claims from a token do not grant access. Duplicate subjects or principal IDs refuse code-flow setup. Existing delegation-parent and residency policies still apply.

## Browser behavior and callback ownership

Use the configured public origin's `/login` page and select **Sign in with your organization**. Keep serves the callback on the same browser surface as `/console`. The HTTPS proxy must preserve the configured Host; Keep does not derive its public origin or callback from forwarded headers. This feature does not configure DNS, TLS, a proxy, public hosting or an identity-provider client.

Each sign-in creates independent state, nonce, PKCE verifier and a bounded browser transaction. The temporary `__Host-keep_oidc` cookie is HttpOnly, Secure and SameSite=Lax for the top-level GET callback, and expires with the transaction policy. A successful callback creates a fresh `keep_session` cookie with HttpOnly, Secure and SameSite=Strict. The transaction is consumed before exchange and cannot be reused. Duplicate callback parameters, another browser binding, expired state and mismatched nonce/issuer/audience refuse. Optional callback `iss` must match the configured issuer.

Token exchange sends the code, exact callback and verifier to only the configured token endpoint, using `client_secret_basic`. Redirects are refused. Exchange and verification share the shorter of the configured acquisition timeout and remaining transaction lifetime, with cancellation passed to the verifier port. The response body has the configured byte bound. Session minting rechecks the fresh clock and verified token expiry after asynchronous verification. A lost response, timeout or refusal consumes the transaction; Keep does not automatically retry the code exchange. Start a new browser sign-in after inspecting any unresolved external outcome.

Code mode disables the raw assertion form at `POST /login` and raw assertion acquisition at `POST /auth/session`. Omitting the server identity layer cannot turn an already configured code-flow runtime into personal owner mode. The browser console uses the authenticated principal and existing tenant/permission checks. The session ID stays in an HttpOnly cookie; it is not a CLI credential or a query parameter.

Visit `/login` while signed in to open the console, rotate the session credential or use **Log out**. Rotation requires the same origin and CSRF token. It replaces the cookie, CSRF token and command authority reference while preserving the original absolute session expiry. Commands bound to the old credential remain held. Logout requires the same-origin request and the session's CSRF token, destroys the server session and clears its cookie. Restart loses all process-local sessions and pending login transactions; users sign in again. Client secrets, authorization codes, tokens, verifiers and session IDs are excluded from diagnostics and audit payloads. Protocol redirects necessarily carry the authorization request's state/nonce/challenge to the configured issuer; keep proxy/access logs private and avoid recording callback queries.

## Current verification and authority limits

The strict code-flow verifier admits RS256 RSA public keys of at least 2048 bits, with one unambiguous `kid`, compatible signing metadata and no private key parameters. It uses the existing strict JSON parser: unique object keys, valid UTF-8 and **integer-only** NumericDates/JSON numeric claims. It requires transaction-bound nonce, `iat` freshness, expiry, optional `nbf`, exact issuer and a single trusted client audience; optional `azp` must match the client. Fractional/exponent numeric claims and unsupported JOSE critical headers refuse in this profile. Legacy assertion verification retains its existing semantics.

Without `login.keys`, verification uses the admitted protected local JWKS file. This deliberate static mode requires operator-managed key replacement and restart. It performs no metadata or JWKS requests.

For bounded remote refresh, add this complete optional object to `login`. Replace the metadata URL and review the explicit policy values for the deployment:

```json
"keys": {
  "metadataUrl": "APPROVED_HTTPS_METADATA_ENDPOINT",
  "ttlMs": 300000,
  "cooldownMs": 30000,
  "timeoutMs": 5000,
  "maxResponseBytes": 65536,
  "maxKeys": 16,
  "maxRetiredKeys": 128
}
```

The remote mode starts without an admitted network snapshot. It fetches only the pinned metadata URL and `jwksUri`. Metadata must match the exact issuer, authorization, token and JWKS endpoints and support code, RS256 and S256. Redirects refuse. Each refresh has one acquisition timeout and a byte bound for each document. Concurrent callers share one refresh; a cancelled caller leaves other callers' refresh intact. Unknown key IDs trigger refresh only outside the cooldown. Ordinary failed refresh retains an existing snapshot only until its original TTL. Expired keys cannot verify a new login.

Replacement validates the full bounded public keyset before admission, including minimal RSA integer encodings and unique public material. Removing a key retires both its ID and public material for this process. Changing material under an existing ID or reintroducing retired material refuses the replacement. The retired-key capacity requires operator reconciliation when full. Retirement history is process-local and is lost on restart; persistent incident/retirement custody remains open. An expired snapshot or failed network acquisition never falls back to the static file in remote mode. Key rollover changes future login verification; existing opaque sessions retain their independent session lifetime.

Code-mode human project commands carry a separate, non-bearer reference bound to the original session, issuer, subject and tenant. The API captures it from the authenticated session; the browser console forwards it through its trusted server bridge. Request JSON cannot supply it. The reference cannot authenticate an HTTP request and excludes the cookie, CSRF token and raw IdP tokens. Durable commands and goal children preserve their original reference.

Queue dispatch, recovery, resume and the supported default native model/edit/test entry points recheck that session without extending idle expiry. Logout, local revocation, rotation, idle/absolute expiry or restart prevent later dispatch under the old reference. A fresh login cannot reauthorize an old command. A refusal records prevented new dispatch; an effect already sent to a remote provider can continue and requires its own outcome evidence. Source fixtures cover the default native command path, model retry/stream boundary and late independent test-process spawn. Code-mode human custom, generic and domain execution paths with missing effect checks are held. Stronger isolation configurations and the optional Windows boundary adapter also remain held for code-mode human commands until their final dispatch seam carries the session check. Keep preserves the configured isolation floor. Completing those platform paths remains required work. Personal mode and independent delegated-agent grants keep their existing authority semantics.

The roster and delegation-parent mapping remain startup snapshots. Directory/membership refresh and an upstream user-disable or incident revocation channel remain open. Session expiry requires a new login; this implementation stores no OAuth refresh token. Actual issuer/client deployment, independent custody, persistent retirement and installed enterprise qualification remain open. The revocation evidence here covers the session-bound durable project path. Other request-scoped effect surfaces remain held for code-mode human sessions until their late-session integration is complete.

## Supported prototype routes

Code-mode human sessions use an explicit route allowlist. These routes retain their existing tenant, permission and input checks. A supported command route still requires its original live session and the supported default native effect path.

| Surface | Method | Supported routes |
| --- | --- | --- |
| JSON API observations | GET | `/projects`, `/project`, `/project/jobs`, `/project/export`, `/project/goal` |
| JSON API session-bound commands | POST | `/project`, `/project/resume`, `/project/goal`, `/project/goal/advance`, `/project/goal/control` |
| Browser project observations | GET | `/console`, `/console/project`, `/console/export`, `/console/style.css`, `/style.css` |
| Browser session-bound command | POST | `/console/resume` |
| Browser authentication | GET | `/login`, `/auth/oidc/start`, `/auth/oidc/callback` |
| Browser credential controls | POST | `/auth/oidc/rotate`, `/logout` |

`GET /health` remains an unauthenticated liveness response. Raw assertion acquisition remains disabled in code mode. Authenticated code-mode human requests outside the allowlist are held before route-specific handlers, including front-door messages/offers, fleet operations, telemetry export, human merge/revert, review decisions, delegation issuance/revocation, client signing, memory routes, worker control, cancellation and project lifecycle mutation. Unproved GET routes and newly added routes are held too. These handlers return HTTP409 with a route-held response; missing or revoked session authority returns403. Existing authentication/protocol refusals retain their own status codes.

Personal mode, legacy assertion identity mode and independently delegated agent sessions retain their existing route and authorization checks. The code-mode human holds preserve the remaining work: add session checks at each actual dispatch or mutation boundary, prove allowed and refused effects, then admit each route explicitly. The allowlist does not establish revocation across every platform surface or terminate effects already dispatched.

The protocol checks follow the OpenID Provider metadata validation and JWT issuer/subject/algorithm guidance. The TTL, cooldown, retirement policy and session command reference are this restricted profile's implementation choices.

https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationValidation

https://www.rfc-editor.org/rfc/rfc8725.html#name-validate-issuer-and-subject

Before live qualification, supply the approved issuer metadata, registered client and exact callback/public origin, runtime secret reference and custody owner, tenant roster/policies, network/TLS authority, and bounded allowed/refused users. Qualify the exact installed artifact, real code exchange, tenant isolation, rotation/revocation contract and recovery behavior independently of these source fixtures.
