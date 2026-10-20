# Dependency status

Checked **October 20, 2026**. Keep's source checkpoint and its downloadable preview have separate identities. Historical workflow qualification records what passed on those bytes; it is not continuing security clearance for every dependency.

Use **Node 22.23.3 or later on the supported Node 22 line** for current Keep source. [Node 22.23.3](https://nodejs.org/en/blog/release/v22.23.3) includes Undici 6.28.1 and OpenSSL 3.5.8. The previously documented 22.23.2 runtime predates those fixes. This guidance does not change an old archive or transfer its installed checks to a new runtime.

The [October Node security announcement](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases) schedules additional fixes on or shortly after October 21. Their details were unavailable at this check. The controlled OpenClaw workflow used Node 24.22.0; compatibility and a successful workflow do not establish that it contains future fixes.

The current combined Keep/OpenClaw/Codex download remains unpublished. Its admission review found advisory-matched dependencies in bundled npm installer tooling and in the source-derived Codex CLI graph. Those version matches require location, feature and call-path assessment; they do not by themselves prove an exploitable Keep path. Updating the stock Codex version or disabling shell tools is insufficient to establish the generation-only boundary. Final distribution also needs matching native notices and exact-artifact checks.

The selected Bubblewrap 0.13.0 identity is outside the three upstream advisory ranges inspected on October 20. That statement covers those advisories, not all possible vulnerabilities. Historical `0.0.4-preview.1` remains affected; its bytes and warning are preserved in [Security](../SECURITY.md).

The next combined release needs the actual patched runtime and dependency closure, applicable native attribution, a matching installed archive and its remaining admission/qualification. Source checkpoints can publish working scoped repairs with these limitations. See [evidence](evidence.md), [release identities](../KEEP_RELEASE.md) and [Codex status](codex-project.md).

The owned generation.2 engine now compiles with Rustls 0.23.46 and retains the empty-tool policy. The [genuine follow-up](genuine-codex-walkthrough.md) used checksum-verified Node 22.23.3, with observed Undici 6.28.1/OpenSSL 3.5.8, and OpenClaw Node 24.22.0. These observations close the named native build/runtime and genuine-case gaps at their scope; complete attribution, remaining advisory applicability and final distribution qualification remain open. No global runtime update was required.
