# Dependency status

Checked **November 12, 2026**. Keep source requires **Node 22.23.5 or later on Node 22**. The selected Linux x64 appliance runtime is checksum-pinned Node 22.23.5, including the November 11 HTTP/TLS security fixes. See the appliance receipt for exact-image qualification.

https://nodejs.org/en/blog/release/v22.23.5

The separate native OpenClaw client needs current runtime admission. Node 24.22.3 is the selected patched candidate. The plugin still declares its historical OpenClaw 2026.10.5 peer contract; current patched OpenClaw compatibility and a complete admitted client closure remain open. Use the current admission requirements for new account workflows.

https://nodejs.org/en/blog/release/v24.22.3

https://github.com/openclaw/openclaw/blob/main/CHANGELOG/2026.10.9.md

Runtime choices apply per workspace or guest. Retained release and execution records keep their original runtime identities and scope.

## Historical October 20 assessment

Checked **October 20, 2026**. The source and download have separate identities. The historical results below apply to their recorded dependencies and routes.

The October 20 guidance selected **Node 22.23.3 or later on Node 22**. [Node 22.23.3](https://nodejs.org/en/blog/release/v22.23.3) includes Undici 6.28.1 and OpenSSL 3.5.8. The earlier 22.23.2 runtime predates those fixes. A different runtime needs its own installed checks.

The [October Node security announcement](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases) schedules additional fixes on or shortly after October 21. A documentation refresh at **October 21, 2026, 01:56 UTC** rechecked that announcement and the [official release index](https://nodejs.org/dist/index.json): the latest listed Node 22 and Node 24 versions remained 22.23.3 and 24.22.0, and the announcement still described the security releases as forthcoming. No new runtime was installed or qualified by that refresh. The controlled OpenClaw workflow used Node 24.22.0; compatibility and a successful workflow do not establish that it contains future fixes.

The combined preview's admission review found advisory-matched dependencies in bundled npm tooling and the source-derived Codex CLI graph. Exploitability depends on location, enabled features and call paths. The generation-only boundary needs checks beyond a Codex version change or disabled shell tools. Matching native notices, source support and exact-artifact observations accompany the release.

The selected Bubblewrap 0.13.0 identity is outside the three upstream advisory ranges inspected on October 20. That statement covers those advisories, not all possible vulnerabilities. Historical `0.0.4-preview.1` remains affected; its bytes and warning are preserved in [Security](../SECURITY.md).

The combined route runs its self-contained core directly with patched Node 22 and installs the dependency-free local plugin through an existing supported OpenClaw. Node 22.23.3 bundles npm 10.9.9 with additional advisory matches, including package-retrieval/signature tooling; do not use that installer for this route. OpenClaw/Node 24 installer findings remain disclosed and are not a blanket approval of arbitrary npm queries, packages, Bun or unrelated extensions. See [evidence](evidence.md), [release identities](../KEEP_RELEASE.md) and [Codex status](codex-project.md).

The owned generation.2 engine now compiles with Rustls 0.23.46 and retains the empty-tool policy. The [genuine follow-up](genuine-codex-walkthrough.md) used checksum-verified Node 22.23.3, with observed Undici 6.28.1/OpenSSL 3.5.8, and OpenClaw Node 24.22.0. The source-support archive contains notices/provenance for the conservative declared graph, recovered notice inputs and all 12 MPL-only source packages. The matching release record supplies the actual distribution identity, supported conditions and installed observations. The results cover that declared graph and runtime profile.
