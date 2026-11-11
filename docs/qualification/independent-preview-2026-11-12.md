# Independent workspace verification — November 12, 2026

The published .21 download and the .22 source build reproduced outside the development server. Required-jail dependency preparation remains conditional on a separately qualified host: the clean runner denied network-namespace setup.

| Check | Independent environment | Observed result |
|---|---|---|
| Published .21 archive | Fresh Ubuntu 24.04 x64 VM, Node 22.23.4, empty application home | Both scripted demos, saved instance/console lifecycle, authenticated proposal export and offline patch verification passed. No source checkout or development cache. |
| Native patch publisher | Same fresh VM and actual published package root export | Candidate contents, original inputs, checksums and evidence readback passed. |
| Source .22 | Separate fresh x64 VM, exact public commit, fresh npm dependencies and Rust 1.97.1 | Standard `npm run build` and public API import passed. All three rebuilt native executables exactly matched the published checksums. |
| Bundled generation engine | Fresh x64 VM, empty account home | Native executable launched and reported its expected version; login status correctly reported logged out. No live generation was attempted. |
| Spark portable workflow | ARM64 NVIDIA GB10, separately downloaded Node 22.23.4, public release inputs | Both demos, lifecycle and export passed. Native capture returned `UNSUPPORTED`; the bundled native/generation executables target x64. This is portable-workflow evidence, not an ARM64 native release. |
| Namespace helper build | Fresh VM, public pinned Dockerfile and upstream source | Rebuilt helper matched the existing admitted SHA-256 exactly. |
| Required-jail preparation | Fresh x64 VM with a protected, admitted helper | Namespace setup refused before the installation check could complete. Independent positive preparation remains unverified on this restricted host. |

The tested combined archive is `keep-combined-0.0.21-preview.1-linux-x64.tar.gz`, SHA-256 `7b22762a48a0f6e1e26db342b51ef211035db0cf1b88619a720324b3ef5f3fca`. The source build used commit `f4fd9e35f7655c646998c0618fa37639e10a24a1`. Its fresh compiler/build gate passed and produced the same native client, supervisor and capture bytes as the release. This is a build result; the complete runtime test suite was not run by that build job.

Published-download and native-consumer run:

https://github.com/RedRookAI/keep-research-preview/actions/runs/43118531712

Source-build run:

https://github.com/RedRookAI/keep-research-preview/actions/runs/43122194373

Machine-readable subjects, receipts and preserved failures:

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/qualification/independent-preview-2026-11-12.json

## Reproduce the account-free check

Use an unprivileged Linux x64 account with supported Node 22 and Git. Download these public files into a new owned directory:

https://github.com/RedRookAI/keep-research-preview/releases/download/keep-preview-2026-11-11.2/keep-combined-0.0.21-preview.1-linux-x64.tar.gz

https://github.com/RedRookAI/keep-research-preview/releases/download/keep-preview-2026-11-11.2/installed-preview-2026-11-11.2.mjs

```sh
printf '%s\n' \
  '7b22762a48a0f6e1e26db342b51ef211035db0cf1b88619a720324b3ef5f3fca  keep-combined-0.0.21-preview.1-linux-x64.tar.gz' \
  'dc93efe0fb023e5251010a13371f9731ab2e27b3e5e5fc4dad1b164f1ea55952  installed-preview-2026-11-11.2.mjs' \
  | sha256sum --check
node installed-preview-2026-11-11.2.mjs \
  keep-combined-0.0.21-preview.1-linux-x64.tar.gz \
  7b22762a48a0f6e1e26db342b51ef211035db0cf1b88619a720324b3ef5f3fca
```

The harness creates its own empty home and fixture directories, extracts the archive and records command outcomes. It uses the published runtime directly. Account-free generation responses and decisions are authored fixtures. A genuine account walkthrough needs the operator's own login and remains separate.

## Required-jail host prerequisite

The fresh runner's `/opt` directory was mode 0777. Installing the helper beneath it failed the existing protected-ancestry check. A dedicated root-owned directory under `/var/lib` satisfied static helper admission without changing shared directory permissions.

The actual required SDK preflight still could not confirm namespaces or resource-limit setup. A separate unconditional probe of the exact rebuilt helper reported:

```text
bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted
```

The host had `apparmor_restrict_unprivileged_userns=1`. Host namespace, AppArmor and sysctl policy stayed unchanged. The observation establishes a denied namespace/network operation; it does not establish a successful dependency installation or attribute every failure to one policy switch. Static helper identity alone is insufficient to qualify this profile.

Actual helper/host capability probe:

https://github.com/RedRookAI/keep-research-preview/actions/runs/43121418313

Structured required SDK preflight:

https://github.com/RedRookAI/keep-research-preview/actions/runs/43120379766

The initial helper-path failure, missing-log diagnostic failure and corrected Rust installer bootstrap are retained in the JSON record. One workflow dispatch used an earlier revision and ran no relevant slice; its green status is excluded. The decisive namespace and build checks use separate immutable branch revisions and actual executed steps. Rust bootstrap used the documented per-command self-update suppression for its new private toolchain home:

https://rust-lang.github.io/rustup/basics.html

## Scope and storage

These are developer-administered fresh-environment checks of public inputs. They establish the listed installation, workflow and build outcomes. Live model quality, live organization custody, maximum resource profiles, production-native authority and whole-platform completion remain outside this result.

Large downloads and builds for this verification ran on the Spark or disposable CI VMs. No large artifacts or builds were added to Hetzner. The Spark's completed test downloads, runtime and extracted fixtures were removed; 24 KiB of receipts and logs remain in its owned workspace.
