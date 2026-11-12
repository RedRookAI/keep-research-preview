# Start a local Keep instance

Use `keep instance` to save a repository setup and operate its project worker. The [combined preview](combined-preview.md) includes these commands; the historical 0.0.12 archive predates them.

## Save the setup

Choose an existing repository and its check command. For a Node project checked with `npm test`:

```sh
keep instance init /absolute/path/to/my-keep \
  --repository=/absolute/path/to/my-project \
  --test-command=npm --test-args='["test"]'
```

The instance directory must be new, outside the source, with an existing parent. Keep creates private `data/` and `workspaces/` directories and saves an `instance.json` profile. It pins the current branch's commit. Use `--branch=<existing-branch>` to select another branch. Reconcile the saved revision explicitly before starting against an advanced branch.

The profile stores configuration without account secrets or owner tokens. To save Codex generation settings at init:

```sh
keep instance init /absolute/path/to/my-keep \
  --repository=/absolute/path/to/my-public-project \
  --test-command=npm --test-args='["test"]' \
  --project-model=codex \
  --codex-processing=owner-public-repository \
  --codex-executable=/absolute/path/to/keep-install/engines/codex-generation.2/bin/codex \
  --codex-model=your-supported-codex-model \
  --codex-max-invocations=2 \
  --codex-max-prompt-bytes=65536 \
  --codex-max-output-bytes=262144 \
  --codex-timeout-ms=180000
keep instance status /absolute/path/to/my-keep
```

Select an existing native engine and an account-supported model. The example engine path belongs to an extracted combined installation; substitute its actual location. Keep checks version and existing login metadata. Init/status make no generation calls; status shows the saved model, engine and limits.

The four limits must be positive safe integers. Timeout is capped at **2147483647 milliseconds**. They bound CLI invocations, submitted prompt bytes, captured output bytes and local process time. The [Codex guide](codex-project.md) explains subscription accounting and model-token limits. Public owner-repository processing consent remains explicit.

Each flag is accepted once and overrides supported `KEEP_PROJECT_MODEL`, `KEEP_CODEX_*` or helper environment settings. Profile changes apply after stopping/restarting the owned instance. Missing engine/login, invalid limits and untrusted helpers produce corrective options. Failed validation removes empty setup directories and preserves unexpected nonempty state.

Without a configured project model, the gateway/worker starts paused with deterministic fixture responses selected. Repository dependencies must be available in the eventual workspace before checks can pass.

## Prepare repository checks

`keep instance status` shows the checker, arguments, detected package manager/lockfile and missing prerequisite paths. Node dependency checks look for declared runtime/development package metadata; the configured executable checker verifies behavior.

Keep clones the pinned source into `workspaces/project`. Ignored source dependencies are excluded. Missing checker prerequisites hold the project before generation. Prepare that workspace, then resume the same held run:

```sh
keep project resume ACTUAL_RUN_ID \
  --capability=repository-check-prerequisites \
  --evidence=owned-workspace-prepared
```

New materializations copy Git objects independently. Older local clones may share object inodes that required mode refuses. Inspect those workspaces before replacing them; Keep preserves unresolved work.

For a prepared repository, use the checker without a preparation recipe. Add required files/directories at init with `--test-prerequisites='["relative/path"]'`; paths must stay inside the repository and outside Git metadata. To materialize and inspect without installing:

```sh
keep instance prepare /absolute/path/to/my-keep
keep instance status /absolute/path/to/my-keep
```

If prerequisites are missing, prepare reports the owned workspace path and next action. Supply dependencies there with your selected toolchain, then run prepare again. Independent checks use a disposable copy with those dependencies; the source remains separate.

For offline npm preparation, select an existing Node distribution containing `bin/node` and `lib/node_modules/npm/bin/npm-cli.js`, outside the source and workspaces:

```sh
keep instance init /absolute/path/to/my-keep \
  --repository=/absolute/path/to/my-project \
  --test-command=/absolute/path/to/selected-node/bin/node \
  --test-args='["--test","test/check.cjs"]' \
  --workspace-preparation=npm-offline \
  --workspace-toolchain=/absolute/path/to/selected-node \
  --test-namespace-jail=required \
  --test-jail-executable=/absolute/protected/keep/bwrap
keep instance prepare /absolute/path/to/my-keep
```

The selected toolchain is mounted read-only. Keep hashes its two entry files and rechecks them before dispatch; select a dedicated Node distribution rather than a broad system directory. Since source .22, a fixed Node preflight runs inside the required sandbox before repository code or npm. A failed preflight retains the hold. Check the helper, selected runtime and host namespace/AppArmor/container policy before supplying packages.

Installation runs `npm ci --offline --ignore-scripts` with audit/funding disabled, global mode off, an explicit workspace prefix/cache and separate empty private user/global npm configuration files. Those files remain under workspace Git metadata. Preflight and install share the preparation deadline; CPU/output limits apply to each process. Both must confirm the required boundary. Preparation has no network or extra writable host paths, and unsupported setup refuses.

Commit `package-lock.json` or `npm-shrinkwrap.json` in the selected revision. Supply any needed existing offline cache in `workspaces/project/.keep-preparation-cache`, then explicitly retry prepare. Missing cached packages, lockfiles or required build scripts retain a hold. Already prepared repositories using other package managers can still run their checker.

Stop the owned worker before preparation. Active/unresolved workers, pending startup or overlapping setup refuse. Preparation saves an integrity hold in workspace Git metadata before dispatch. Failed/uncertain completion retains it. Inspect process state and reconcile source/workspace tracked bytes with their saved identities before explicitly rechecking. Keep leaves source restoration to the operator.

Environment alternatives are `KEEP_TEST_PREREQUISITES_JSON`, `KEEP_WORKSPACE_PREPARATION=npm-offline` and `KEEP_WORKSPACE_TOOLCHAIN`.

The scoped unprivileged consumer observed empty-cache refusal, an explicit seeded retry, TypeScript 5.9.3 installation and a passing transpilation checker under required namespaces. The release receipt identifies the tested archive and separate source observations.

## Issue a restricted OpenClaw client for this instance

`client-issue` requires source .26 or later. The .21 download and .25 appliance candidate at `6a1d880` use environment-configured issuance.

With the personal public-repository Codex setup saved and worker stopped, choose a private directory outside source/workspaces and a future expiry:

```sh
mkdir -m 700 /absolute/private/client-directory
keep instance client-issue /absolute/path/to/my-keep \
  --profile=/absolute/private/client-directory/client.json \
  --token-file=/absolute/private/client-directory/client-token \
  --agent-id=my-openclaw \
  --expires-at=YOUR_FUTURE_ISO_TIMESTAMP
keep instance status /absolute/path/to/my-keep
keep instance start /absolute/path/to/my-keep
```

Issuance uses the saved repository, checker, engine, model, limits and data directory. It checks engine/login metadata without generating or changing invocation allowance. The client receives restricted `change.solve` authority. Private profile/token files keep their expiry and no-overwrite checks.

After issuance and profile readback, Keep saves only the `KEEP_OPENCLAW_CLIENT_PROFILE` reference in `instance.json`. Later starts reuse it; status shows the reference. Follow the [client guide](openclaw-client.md) to give the plugin its restricted credential.

Active/unresolved workers, pending startup, concurrent controls or an existing client binding refuse issuance. Reconcile the original instance first. If issuance or saving its reference is uncertain, inspect retained files, grants and `instance.json` before retrying. Usage history and existing bindings remain intact. Use owner revocation to retire a client.

## Start and inspect

```sh
keep instance start /absolute/path/to/my-keep
keep instance status /absolute/path/to/my-keep
keep instance projects /absolute/path/to/my-keep
```

Start prints the local API/console addresses, worker identity, retained-state location, private diagnostic path and lifecycle commands. It chooses a free loopback port by default. Use `--port=7788` for a fixed port; an occupied port refuses. `--paused` starts a configured worker with dispatch paused.

The worker survives the launching terminal. Lifecycle commands authenticate from its private token file without printing it. Worker pairing output is suppressed; errors go to private stderr. Treat `data/native-workers/` records as private operational data.

## Open the project console

Open the printed address in a browser and sign in with the instance's private `data/gateway-token`. On a remote host, use an SSH tunnel from your browser's computer. The password form sends the credential to the same origin and sets an HttpOnly, SameSite cookie. Keep this owner credential private.

Choose **Submit a repository goal**. The form uses the saved repository, provider, checker and limits, then opens a retained background project. Paused dispatch leaves it queued. Missing setup/dependencies appear as a hold or failure with the next action.

Keep the form until the project appears. Its submission key survives refresh/history. If a response is lost, inspect retained projects and recover with the unchanged goal and key. A changed goal under that key refuses. A fresh key can start another job; sign-in remains required.

The console shows stages, jobs, pending decisions, diff and check results. Inspect a pending step before approving/declining it, then approve or veto the exact proposal. Check the delivery result: a workspace change and a source landing are recorded separately. Refresh reads persisted state without replaying work.

Browser actions use the same project authority checks plus Host, Origin and CSRF checks. Organization deployments use their configured identity sessions; header-only custom principal resolvers cannot use owner browser sign-in. Opening a project leaves generation stopped; dispatch uses its configured controls.

**Request cancellation** targets a queued/running job for users with solve permission. Refresh to inspect the resulting state. Remote work can remain uncertain after a local cancellation; reconcile it before retrying. Focused checks covered cancelling one queued job while a separate project completed. The historical 0.0.12 download predates this control. The legacy review queue remains separate from project controls.

## Stop and reopen

```sh
keep instance stop /absolute/path/to/my-keep
keep instance status /absolute/path/to/my-keep
keep instance start /absolute/path/to/my-keep
```

Stop authenticates the recorded worker identity and requests API shutdown. Active or queued work refuses shutdown; inspect or cancel it first. State survives stop/start, and startup leaves model requests undispatched.

An existing live worker is reported rather than duplicated. A lost startup acknowledgement retains `startup-pending.json` and holds relaunch. Inspect the instance's private diagnostic/lifecycle records to resolve its state before another start.

## Selecting an existing required-jail helper

For a qualified Bubblewrap 0.13.0 helper in a protected root-owned installation, add:

```sh
  --test-namespace-jail=required \
  --test-jail-executable=/absolute/protected/keep/bwrap
```

Init saves the path and verifies fixed bytes/protected ownership without executing the helper. Missing or untrusted helpers identify the correction. Omitting the path selects `/opt/keep/bubblewrap/0.13.0/bwrap`. The selected path requires required mode. Other explicit modes are `--test-namespace-jail=best-effort` and `--test-namespace-jail=off`; environment alternatives are `KEEP_TEST_NAMESPACE_JAIL` and `KEEP_TEST_JAIL_EXECUTABLE`.

`keep doctor` checks helper prerequisites without a model call. Actual repository checks must also confirm namespace setup. Host namespace permissions remain required; initialization leaves global tools and policy unchanged. See the [execution boundary](../SECURITY.md#opt-in-required-project-boundary-experimental).
