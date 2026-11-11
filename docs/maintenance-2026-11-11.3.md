# November 11 source update — session authority and native patch application

Development source remains **0.0.21-preview.1**. The currently published combined download is **0.0.20-preview.1**, with its original source and qualification. This record describes subsequent source work.

## Organization key and session lifecycle

The configured code-flow prototype now supports pinned metadata/JWKS refresh with bounded acquisition, shared concurrent refresh, an unknown-key cooldown and no expired-key fallback. Remote mode checks the configured issuer and exact endpoint metadata. Static protected-file mode remains explicit. Removed keys and public material retire for the process lifetime; persistent retirement and upstream membership/revocation require further integration.

Project commands retain a non-bearer reference to their original browser session. The supported default native path checks it at queue/recovery/resume, model sends and retries, edits and the independent test-process entry point. Logout, rotation, expiry and restart prevent later dispatch under that reference. A fresh login cannot authorize an old command. Already dispatched effects retain their own unresolved outcome.

Code-mode human API/browser routes use an explicit allowlist. Unsupported memory, fleet, telemetry, review and other effect routes return a hold before entering their handlers. Custom/domain and stronger-isolation paths without final session checks also remain held. The configured isolation floor stays in force. Personal, legacy assertion and independently delegated-agent behavior retain their existing authorization. The complete supported/held route list and remaining platform work are in the organization guide.

Controlled checks include actual default-path editing after two model fixture responses, revoked queued commands with zero model dispatch, revocation after one send preventing later model/edit work, rotation preventing reuse, goal-child holds, and stronger-boundary refusal. These fixtures establish the observed local prototype behavior. Live approved issuer/client/callback, credential custody, current membership and installed enterprise acceptance remain open.

## Native patch application

The SDK now exposes `publishPackagedNativePatchApplicationV1`. It captures a supported archive, overlay/carriers, audit and review record, derives the result and Cargo checksum adapter, and publishes a candidate into a separate owned workspace. Intent/attempt records precede effects. Atomic no-replace publication preserves prior candidates; input identity, staged descendant and byte readbacks precede the success record. Failure after dispatch records an uncertain outcome and retains the candidate for inspection.

The supported package is the existing fixed `curve25519-dalek@5.0.0` codec profile. Exact review-input references are retained with status `unverified`; evidence grants no build, admission or launch authority. Candidate permissions are owner-reversible. Publication assumes cooperating owned writers and a trusted administrator; a hostile same-user staging-name race can leave a visible uncertain candidate. The detailed API and trust boundary are in the native application guide.

The native lane passed three owned-directory Rust checks, ten application/audit/structural checks, and focused native/SDK publication and refusal checks. Actual races cover source replacement, staged file/directory/carrier substitution and post-rename file or ledger alteration. Post-publication alterations produce `unknown` and no successful SDK return. An offline installed minimal SDK also invoked the freshly compiled native application as an unprivileged user. Only the audit-plan structural exception justified by this actual consumer was removed. The ABI adds one reviewed syscall site; the exact unsafe-site gate advances from 56 to 57 with its mutant check intact.

Initial Rust syntax/import build errors were corrected before passing builds. Debug binaries and the final release binaries have distinct subjects; their evidence must retain those identities. No whole-suite, maximum application profile, live review/custody or production-native admission follows from these scoped results.

## Integrated evidence

Clean TypeScript emission and **139/139** affected organization, gateway, console, provider, project-test, workflow and CI-coordinator checks passed after integrating both lanes, with zero failures, skips or cancellations. A separate review found a server/library identity-composition gap: server-only code-flow identity could authenticate while app-level checks stayed inactive. The correction requires the exact app identity, with refusal before listening or entering a handler. Clean emission and **81/81** affected follow-up checks passed, including valid-session mismatch refusal and supported exact-identity operation. The partial hosted profile now includes the refresh and admission regression files. Previously passing unchanged native stages are reused.

The unchanged gated release builder then verified the pinned toolchain and built three fresh static PIE executables in an owned lane, using one offline Cargo worker. Release capture SHA-256 is `d124a4b5b9198f84be5d45c0617cf1bcae3e7fe483d932952825cb7bfb6b2b8c`. Two selected ordinary-capture and unprivileged offline installed-SDK checks passed against these release bytes. The native package manifest/mode assertion also passed after verified handoff. These are release component observations; exact combined-archive qualification follows separately. No shared toolchain or host service changed.

The earlier source checkpoint also has successful hosted evidence: Node 22.23.4, locked script-disabled install, emitting compilation, notices and **129/129** selected tests. That observation belongs to commit `274a0655238bb6ea9a9f6040cefcabd9fbd83880`.

https://github.com/RedRookAI/keep-research-preview/actions/runs/43103953966

Organization setup and exact route scope:

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/organization-login.md

Native application API and outcome handling:

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/native-patch-application.md
