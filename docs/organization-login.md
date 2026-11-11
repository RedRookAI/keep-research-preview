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

Visit `/login` while signed in to open the console or use **Log out**. Logout requires the same-origin request and the session's CSRF token, destroys the server session and clears its cookie. Restart loses all process-local sessions and pending login transactions; users sign in again. Client secrets, authorization codes, tokens, verifiers and session IDs are excluded from diagnostics and audit payloads. Protocol redirects necessarily carry the authorization request's state/nonce/challenge to the configured issuer; keep proxy/access logs private and avoid recording callback queries.

## Current verification and authority limits

The strict code-flow verifier admits RS256 RSA public keys of at least 2048 bits, with one unambiguous `kid`, compatible signing metadata and no private key parameters. It uses the existing strict JSON parser: unique object keys, valid UTF-8 and **integer-only** NumericDates/JSON numeric claims. It requires transaction-bound nonce, `iat` freshness, expiry, optional `nbf`, exact issuer and a single trusted client audience; optional `azp` must match the client. Fractional/exponent numeric claims and unsupported JOSE critical headers refuse in this profile. Legacy assertion verification retains its existing semantics.

JWKS are loaded from the already admitted protected local file. `jwksUri` records the selected endpoint for the later refresh implementation; this ticket does not fetch it or refresh keys. The verification and principal-resolution ports accept per-request context for that follow-up. There is no OAuth refresh-token storage, `offline_access` scope or automatic session renewal. Session expiry requires a new login.

The roster and delegation-parent mapping remain snapshots loaded at startup. Session authentication metadata retains original issuer, subject and tenant, but current user-disable, role-change and upstream revocation are not live-refresh guarantees. Existing session revocation primitives and these identity bindings are inputs to the separate revocation work. Do not treat a local session or a file permission check as production-native custody, live enterprise qualification or immediate issuer-side revocation.

Before live qualification, supply the approved issuer metadata, registered client and exact callback/public origin, runtime secret reference and custody owner, tenant roster/policies, network/TLS authority, and bounded allowed/refused users. Qualify the exact installed artifact, real code exchange, tenant isolation, rotation/revocation contract and recovery behavior independently of these source fixtures.
