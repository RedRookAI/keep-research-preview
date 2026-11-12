# Configure a repository goal

The historical **0.0.19-preview.1** combined release includes `keep solve`, the existing-account [Codex role](codex-project.md) and generation-only engine. The [combined guide](combined-preview.md) covers the later .21 archive. For a first look without provider setup, use the [account-free walkthrough](quickstart.md).

## Repository settings

Choose a repository you own or are authorized to process. Keep pins its exact commit and uses a separate directory for working copies.

| Variable | Value |
|---|---|
| `KEEP_REPOSITORY` | Source Git working tree trusted by the current OS user. |
| `KEEP_WORKSPACE_BASE` | Existing directory disjoint from the source: neither may contain the other. |
| `KEEP_REVISION` | Lowercase 40- or 64-hex commit ID present in the source repository. |
| `KEEP_REPO_REF` | Repository identifier as one canonical path component. |
| `KEEP_BASE_BRANCH` | Existing local branch pointing at that exact commit; defaults to `main`. |
| `KEEP_TEST_COMMAND` | Executable for the repository checks. |
| `KEEP_TEST_ARGS_JSON` | JSON argument array, such as `["test"]` for npm; defaults to `[]`. |
| `KEEP_TEST_NAMESPACE_JAIL` | `required`, `best-effort` or `off`. Required mode needs the measured launcher and working namespace setup. |
| `KEEP_TEST_JAIL_EXECUTABLE` | Protected absolute path to the measured root-owned Bubblewrap helper; requires required mode. Default: `/opt/keep/bubblewrap/0.13.0/bwrap`. Exact-byte and trust checks apply. |

Use predefined checks that catch the requested defect and preserve unrelated behavior. Select the [execution boundary](../SECURITY.md#opt-in-required-project-boundary-experimental) before running repository code; default/best-effort mode offers weaker isolation than required mode.

## Provider settings

For Codex, follow the [account and bundled-engine setup](codex-project.md), then return here. It uses your existing login. The [recorded case](genuine-codex-walkthrough.md) shows one completed result.

For an authorized API-compatible provider:

| Variable | Value |
|---|---|
| `KEEP_PROVIDER` | `openai-compatible` or `anthropic-compatible`. The separate `local` mode supplies deterministic fixture responses. |
| `KEEP_PROVIDER_AUTHORITY` | `owner` for a personal configuration. Organization mode has separate identity/custody requirements. |
| `KEEP_PROVIDER_BASE_URL`, `KEEP_PROVIDER_MODEL` | Authorized endpoint and model. HTTPS is required except for explicit loopback endpoints. |
| `KEEP_PROVIDER_LOCATION` | `local` or `external`, matching the processing location; loopback can be inferred as local. |
| `KEEP_PROVIDER_API_KEY`, `KEEP_PROVIDER_API_KEY_FILE`, `KEEP_PROVIDER_API_KEY_STDIN` | Select one credential source; stdin selection is exactly `1`. Owner-local loopback fixtures may omit credentials. Keep secrets outside repositories and logs. |
| `KEEP_REMOTE_PROCESSING_PURPOSE`, `KEEP_REMOTE_PROCESSING_REGION` | Processing purpose and region. |

The API-priced solver needs a known model price. Unknown prices refuse before dispatch, including on loopback. Run `keep doctor` to check configuration. `keep onboard` captures directives; execution settings still come from the configuration above.

## Request and review a proposal

```sh
keep solve "Correct the retry limit; preserve unrelated behavior and tests"
```

Solve accepts a description without options. It requires approval even with `KEEP_PROJECT_POSTURE=autonomous`. Use the printed run and decision IDs:

```sh
keep project resume <run-id> --approve=<decision-id>
```

Keep materializes the pinned source into a workspace and records the diff, rollback information and check results. Use project resume/merge controls for this work; the legacy `keep review` queue is separate. Bind your decision to the displayed proposal digest:

```sh
keep merge <run-id> approve --proposal=<sha256>
keep merge <run-id> veto --proposal=<sha256>
```

The source stays unchanged while review is pending. Check the reported landing result after approval: missing merge authority or a failed/held operation can prevent source delivery. Owner-token and organization session/roster/custody checks also apply to the authenticated remote project endpoint.

Historical receipts identify the tested subjects: [.19 combined archive](qualification/combined-preview-2026-10-20.json), [October 5 installed solve](qualification/installed-solve-2026-10-05.json) and [.12 download](qualification/preview-2026-10-05.json). Broader model success and live organization operation remain unqualified.
