# Sandbox preparation portability — November 12, 2026

The published .21 download and source .22 both completed offline dependency preparation on fresh Ubuntu 22.04 x64 runners, using public inputs and no development cache. Source .22 also correctly refused preparation on a restricted Ubuntu 24.04 runner before launching npm. Host policy was unchanged throughout.

## Why the restricted host refused

Bubblewrap creates a private network namespace so repository commands cannot use the host network. Its attempt to assign the private loopback address failed:

```text
bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted
```

Sandbox setup failed during network-interface configuration, before repository work could execute. The restricted host reported `apparmor_restrict_unprivileged_userns=1`; the fresh host where preparation passed reported 0. These observations are consistent with Ubuntu's AppArmor restrictions on permissions inside unprivileged namespaces. The exact denying rule was not captured; the hosts also differed in other settings.

Ubuntu documents the namespace capability restrictions here:

https://ubuntu.com/blog/whats-new-in-security-for-ubuntu-24-04-lts

No sysctl, AppArmor profile, container policy or shared directory permissions were changed to obtain a pass.

## Changed preparation behavior

Source commit `e53867c1c2add998b9d382f26fc6c7aa97b3b2b7` includes a fixed Node preflight inside the selected required sandbox before npm. It loads no repository code. Preflight and installation share the preparation deadline, and each process must independently confirm its boundary.

A failed preflight now explains the helper, host namespace or selected-runtime setup problem and states that npm was not launched. It retains the integrity hold. A later installation attempt with unconfirmed setup remains a separate refusal; a confirmed sandbox containing an unsuccessful npm command points to retained installation logs and offline dependencies.

Prepared repositories still take the existing no-install path. Keep does not change host policy or weaken the selected sandbox.

## Executed checks

| Subject | Fresh environment | Result |
| --- | --- | --- |
| Actual public .21 archive, SHA-256 `7b22762a48a0f6e1e26db342b51ef211035db0cf1b88619a720324b3ef5f3fca` | Ubuntu 22.04 x64, Node 22.23.4, new application home | Normal instance init, actual empty-cache hold, explicit public-registry cache seed, offline preparation retry and useful TypeScript checker passed. |
| Exact source .22 at `e53867c1c2add998b9d382f26fc6c7aa97b3b2b7` | Separate fresh Ubuntu 22.04 x64, locked npm install and TypeScript emit | Same preparation/checker journey passed with the product preflight. |
| Same source .22 | Separate fresh restricted Ubuntu 24.04 x64 | Normal CLI returned the new preflight diagnostic; no npm configuration/cache/dependency installation was created. Hold retained; original source unchanged. The refusal check passed; preparation remained blocked. |
| Source CI | Fresh Ubuntu 24.04 x64 | 176/176 checks passed across the 20-file partial profile, with no skips. |

Public-download preparation:

https://github.com/RedRookAI/keep-research-preview/actions/runs/43124902024

Exact-source positive and restricted-host refusal:

https://github.com/RedRookAI/keep-research-preview/actions/runs/43125525091

Partial source CI:

https://github.com/RedRookAI/keep-research-preview/actions/runs/43125422956

Machine-readable subjects and receipts:

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/qualification/preparation-portability-2026-11-12.json

## Remaining compatibility work

The Ubuntu 22.04 result qualifies dependency preparation; the bundled AI engine has separate runtime requirements. Full Ubuntu 24.04 sandbox setup still needs a tested integration with its host policy. Any proposed policy installation needs operator review.

Spark uses ARM64. Its portable workflows passed, but the current native tools, helper and generation engine target x64. ARM64 needs platform-specific source changes, builds and qualification, including different syscall filters and library layout handling.

A fresh live-account generation task and broader platform acceptance remain open. The fixtures cover the listed setup behavior. Whole-product completion and production-native authority remain unqualified. Downloads and builds ran on disposable CI VMs.
