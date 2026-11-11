# November 11 source update — organization acquisition and native byte capture

Development source is **0.0.21-preview.1**. The latest combined download remains **0.0.20-preview.1**, with its original November 11 source, hashes and installed qualification.

## Configured organization login

An optional organization profile now supports authorization-code login with browser-bound one-shot state, nonce and S256 PKCE. It uses explicitly configured HTTPS endpoints/callback, a protected client-secret reference, bounded exchange and verification, and opaque server-side sessions. Wrong/replayed callbacks, malformed identities and uncertain responses refuse. Code mode disables raw-assertion shortcuts and prevents an omitted identity adapter from selecting personal owner behavior. Logout checks Origin and session CSRF.

Strict RS256 verification uses the admitted keys and exact issuer/client identity. The profile supports integer JSON numeric claims, unique roster bindings and token-free original issuer/subject metadata. Key refresh, current membership/role revalidation and upstream revocation remain later work. No live issuer/client registration, TLS deployment or independent credential custody has been established.

The new local fixture passed **11/11** checks after clean TypeScript compilation. It uses generated test keys, owned secret files, exact injected HTTPS transport and an ephemeral local socket representing a TLS terminator. Initial typing/fixture-clock failures and two review findings were corrected: expiry is checked after asynchronous verification, and malformed unrelated cookies no longer break login. Fixtures cover deferred expiry without waiting and malformed authentication binding refusal. These observations qualify the configured prototype and its local protocol wiring.

After integration with native capture, clean TypeScript emission and **67/67** affected organization, legacy identity/session/profile, CI-coordinator and public-documentation checks passed, with zero failures, skips or cancellations. The full compiled public API imported successfully. Previously passing native codec/Rust/SDK checks were reused because their input files were unchanged by organization integration.

Setup and supported profile:

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/organization-login.md

## Canonical native capture descriptors

The existing capture boundary now consumes canonical overlay/carrier bytes into a detached immutable descriptor before exposing the result. It checks semantic schemas and the operation/carrier join alongside the existing transport hashes. The descriptor binds original raw and typed identities, base identity, declared result/audit commitments and counts. The P2-D2 profile retains its fixed package scope; patch application and launch authority remain separate.

The matching safe-Rust producer uses the same descriptor without changing the capture wire format. Scoped verification passed **24/24 TS/Rust codec, differential and application checks**, **4 Rust protocol tests**, and **7 affected SDK checks**, including an offline SDK package/install with the freshly built capture executable. Existing literal goldens were preserved. The exact locked Rust compiler and all 146 inventory entries were verified in an owned toolchain prefix; no shared toolchain changed.

The unchanged maximum-size test initially encountered the lifetime memory counter of a shared scope. A single run in a fresh owned transient accounting scope passed: **128 MiB source + 128 MiB carrier**, capture **4912.53 ms**, composed peak **1210494976 bytes**, default deadline **30000 ms**, existing memory assertion **2 GiB**. No limit or assertion changed. That maximum case used the changed SDK with the retained measured .19/.20 capture binary; changed Rust has separate fresh compiler/native-SDK evidence above.

Production-native fixture inventory found an init-asset identity mismatch and unprovided image, cgroup and independent authority inputs. No VM or global host fixture was run. This source update supplies byte validation rather than production-native qualification.

## Downloadable checkpoint

The .20 archive retains its demonstrated personal workflow, authenticated export, prepared/no-install path and paused instance lifecycle. The .21 source changes above are newer than that archive. Historical whole-suite and native evidence remain attached to their tested subjects.

https://github.com/RedRookAI/keep-research-preview/releases/tag/keep-preview-2026-11-11.1
