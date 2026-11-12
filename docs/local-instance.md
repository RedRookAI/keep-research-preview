# Start a local Keep instance

The [combined preview](combined-preview.md) includes `keep instance` to save setup and operate one local project worker. The historical 0.0.12 download predates these commands.

## Save the setup

Choose an existing repository and the command that checks its behavior. For example, for a Node project whose checks run with `npm test`:

```sh
keep instance init /absolute/path/to/my-keep \
  --repository=/absolute/path/to/my-project \
  --test-command=npm --test-args='["test"]'
```

The instance directory must be new, outside the source repository, with an existing parent directory. Keep creates private `data/` and `workspaces/` directories there and saves an inert `instance.json` profile. It captures the current branch's exact commit. Use `--branch=<existing-branch>` to select another branch. Advancing that branch requires deliberately reconciling the saved revision before a new startup; it does not silently change the source used by an existing project.

No API key, owner token or Codex authentication value is saved in the profile. Initialization also accepts explicit generation settings, so you can save the [Codex project role](codex-project.md) without assembling environment variables:

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

Select an existing native executable and a model supported by your account. The engine path above identifies the measured bundled generation engine inside an extracted combined installation; substitute its actual absolute location. Another existing compatible engine can be selected explicitly, with its own qualification limits. Keep checks version metadata and the engine's existing ChatGPT login. Init and status make zero generation calls. Status reports the saved model, executable and caller limits before the first start and alongside the live dispatch state after startup.

The example limits are choices for this instance. Choose each value deliberately; all four must be positive safe integers, and the timeout must be at most 2147483647 milliseconds. They bound CLI invocations, submitted prompt bytes, captured output bytes and local process time. Subscription billing, full model input and output tokens retain the limits described in the Codex guide. Public owner-repository processing consent remains explicit.

These flags write the existing private `instance.json` profile. Each option is accepted once. Environment-based setup remains available: init captures supported `KEEP_PROJECT_MODEL`, `KEEP_CODEX_*` and helper settings, with explicit flags taking precedence. Existing profiles remain readable. Profile edits apply after stopping and restarting this owned instance. Startup and metadata checks leave generation qualification separate.

If the executable, version metadata or login is unusable, init identifies the correction. Sign in through the selected engine's own login command, then retry the corrected init command. Invalid limits and helper selections name their corrective options. Failed validation removes empty setup directories; unexpected nonempty state is retained for inspection. Existing instance directories are always preserved.

Without a project model, Keep starts its real gateway/worker with dispatch paused and the local deterministic stub selected. That mode lets you operate the instance without a model request; it is not live AI generation. Repository dependencies and the configured test command must be available in the eventual project workspace before useful repository work can pass.

## Prepare repository checks

Current source adds a separate workspace-preparation handoff. `keep instance status` shows the saved checker and arguments, detected package manager and lockfile, and missing declared prerequisite paths. Node repositories also check for each declared runtime/development dependency's package metadata. These presence checks leave the executable checker responsible for verifying behavior.

Keep clones the pinned revision into this instance's `workspaces/project` directory. Ignored dependencies in the original source are not copied into it. The software project flow holds before generation when check prerequisites are missing. Correct the owned workspace, then resume that same held project through the existing capability control using `repository-check-prerequisites` and new evidence. Rechecking a missing prerequisite does not rerun generation.

New materializations copy Git objects independently from the original local repository. Earlier local clones may contain shared object inodes, which the required jail refuses. Inspect the retained workspace and its preparation outcome before choosing a replacement; Keep does not detach shared objects or discard an unresolved workspace automatically.

Using your existing configured project client, substitute the actual held run ID:

```sh
keep project resume ACTUAL_RUN_ID \
  --capability=repository-check-prerequisites \
  --evidence=owned-workspace-prepared
```

For an already prepared workspace, use the existing checker and no preparation recipe. You can declare additional required files or directories with `--test-prerequisites='["relative/path"]'` at init. Paths must remain inside the repository and cannot target Git metadata. To explicitly materialize and inspect an instance without installing anything:

```sh
keep instance prepare /absolute/path/to/my-keep
keep instance status /absolute/path/to/my-keep
```

Missing prerequisites return the actual owned workspace path and a next action. Supply the dependencies there with your selected toolchain, then run prepare again. Existing prepared workspaces return readiness without an installation process. Independent repository checks use a disposable copy containing those workspace dependencies; the original source stays separate.

For offline npm preparation, add these settings when creating a new instance. Select an existing Node distribution containing `bin/node` and `lib/node_modules/npm/bin/npm-cli.js`, outside the source and workspace directories:

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

Preparation uses the selected distribution's Node and npm CLI, with their measured bytes rechecked before dispatch. The full selected toolchain is mounted read-only; only the two entry files are hashed. Select a dedicated Node distribution rather than a broad system directory containing unrelated software. Before launching npm, source .22 runs a fixed Node preflight inside the same required sandbox, without loading repository code. A failed preflight reports a helper, host namespace or selected-runtime setup problem and retains the preparation hold. npm has not been launched at that point. Check the protected helper installation and host namespace/AppArmor/container policy before supplying cached packages.

The installation command is `npm ci --offline --ignore-scripts`, with audit/funding disabled, global mode off, explicit workspace prefix/cache, and separate private empty user/global npm configuration files. These empty files remain under the workspace's Git metadata for inspection. Preflight and installation share the configured preparation deadline; CPU and captured-output limits apply to each process. Each launch must independently confirm its required boundary. Keep grants no network access or extra writable host paths, changes no host policy and cannot use process fallback to enable preparation.

Commit `package-lock.json` or `npm-shrinkwrap.json` in the selected source revision. If npm needs cached packages, supply an existing offline cache in this instance's `workspaces/project/.keep-preparation-cache` directory and explicitly retry prepare. Keep does not fetch missing packages or install a toolchain. Other package managers, missing lockfiles, unavailable offline packages and dependencies needing build scripts retain a hold with a next action. Already prepared repositories using another manager can still run their configured checker.

Stop the owned worker before prepare. An active worker or unresolved startup refuses preparation, and the lifecycle/materialization locks prevent overlapping setup commands. A pending integrity hold is saved in the workspace's Git metadata before preparation dispatch. Throws, failed checks and uncertain completion retain it. Inspect the actual process state and reconcile both source and workspace tracked bytes with their saved identities before explicitly running prepare to recheck the hold; source is never restored automatically. A pending hold alone leaves the outcome unresolved. Supported environment selections are `KEEP_TEST_PREREQUISITES_JSON`, `KEEP_WORKSPACE_PREPARATION=npm-offline` and `KEEP_WORKSPACE_TOOLCHAIN`. These settings use the existing private instance profile.

The preparation handoff has source component checks, a real unavailable-helper refusal and a positive unprivileged changed-source consumer. That consumer observed an empty-cache refusal, an explicit seeded retry, installation of TypeScript 5.9.3 and a passing transpilation checker under the required namespace policy. Exact installed-release qualification is recorded separately in the current release receipt; source or hybrid observations do not qualify another archive.

## Issue a restricted OpenClaw client for this instance

This subcommand requires development source .26 or later. The .21 download and .25 appliance candidate frozen at `6a1d880` retain the environment-configured issuance route.

After saving the personal public-repository Codex setup, keep the worker stopped and create a private directory outside the source and workspaces. Choose a future expiry and issue the client using the saved instance:

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

This runs the existing local owner issuance command with this instance's saved repository, checker, engine, model, limits and original data directory. It inspects the engine's version and existing login status; it does not sign in, generate work or change the invocation allowance. The new grant has the existing restricted `change.solve` authority. The private profile and token files retain their normal validation, expiry and no-overwrite rules.

After successful issuance and profile readback, Keep saves only `KEEP_OPENCLAW_CLIENT_PROFILE` in the same private `instance.json`. Status shows that reference, and subsequent start uses it. The token value and account credentials are never saved in the instance profile or printed. Give the plugin its own restricted credential, following the [client guide](openclaw-client.md).

An active or unresolved worker, pending startup, concurrent instance control or existing saved client binding refuses issuance. Stop and reconcile this owned instance first. A failed command saves no new profile reference; inspect any retained private client files and grants before explicitly retrying. If issuance succeeds but saving its reference is not confirmed, retain those files and inspect `instance.json`; do not create another instance or grant to evade uncertain state. This command does not replace an existing client binding or reset usage history. Use the existing owner revocation command when retiring a client.

## Start and inspect

```sh
keep instance start /absolute/path/to/my-keep
keep instance status /absolute/path/to/my-keep
keep instance projects /absolute/path/to/my-keep
```

Start prints the actual local API and console addresses, worker identity, retained-state location, private diagnostic path and lifecycle commands. It uses an available loopback port by default. Choose `--port=7788` when you need a fixed port; an occupied port fails without stopping the existing listener. `--paused` explicitly starts a configured model worker with dispatch paused.

The worker survives the launching terminal. Its owner token remains in a private file and these commands authenticate without printing it. Standard output from the worker's legacy pairing display is suppressed; startup errors go to its private stderr log. Lifecycle records are under `data/native-workers/`. Treat those files as private operational data.

## Open the project console

Open the printed loopback address in your browser; it redirects to `/console`. Sign in with the credential in this instance's private `data/gateway-token` file. The password form sends it to the same origin and installs an HttpOnly, SameSite cookie; the credential is not included in a URL or rendered page. Treat it as an owner credential and keep it private.

Choose **Submit a repository goal** to describe one bounded change using the owner's saved repository, provider, checker and execution limits. The console creates a retained background job and opens its project. Refresh follows progress without starting work. If dispatch is paused, the job stays queued until the owner resumes the worker. Missing setup or dependencies appear as a hold or recorded failure with the next action.

Keep the submission form until the job appears. Its URL retains a submission key across refresh and browser history. If a response is lost, inspect retained projects, then recover with the unchanged goal and the same key. Changing the goal under that key refuses. Starting a fresh form creates a new submission identity; a new key can start another job. The key is not a credential and gives no access without sign-in.

The console lists retained native projects and opens their current stage, pending decision, jobs, activity, proposal diff and repository checks. Unavailable checks appear as unavailable. Approve or decline an exact pending step, or approve/veto the exact displayed proposal. The result distinguishes workspace changes from a recorded source landing; approval alone does not mean the source changed. Refresh shows the latest persisted state without starting or replaying work. The older review queue remains a separate surface for its existing consumers.

The console uses the same project APIs and authority checks as other clients, with Host, Origin and CSRF checks for browser actions. Organization deployments use their configured identity sessions; header-only custom principal resolvers do not fall back to owner browser access. The worker's dispatch remains paused until deliberately enabled through its existing controls. Signing in or opening a project never starts generation.

The combined preview includes **Request cancellation** beside queued
or running jobs for users with project solve permission. It targets that exact
job, leaving other projects alone. The result shows the recorded request and
observed job state; refresh to inspect subsequent activity. A cancellation request
does not undo effects or establish that a remote model stopped. Jobs requiring
reconciliation remain held before any retry. Focused gateway/browser checks passed,
including cancellation of one queued job while a separate project completes its
work. The historical 0.0.12 download predates this addition.

## Stop and reopen

```sh
keep instance stop /absolute/path/to/my-keep
keep instance status /absolute/path/to/my-keep
keep instance start /absolute/path/to/my-keep
```

Stop authenticates and checks the exact recorded worker identity. It requests shutdown through Keep's existing API, without signaling a saved PID or changing a service manager. A worker with active or queued work refuses shutdown; inspect or cancel that work through its normal controls first. State is retained across stop/start, and startup never resubmits a model request to prove readiness.

An existing live worker is reported instead of duplicated. If startup acknowledgement is lost, Keep retains `startup-pending.json` and refuses automatic relaunch. Inspect this instance's private diagnostic/lifecycle records to resolve its actual state. Do not remove another instance's records, reset project state or launch again under a new directory to evade uncertain work.

For a remote development box, the loopback address is local to that box. Use an SSH tunnel to reach it from your own browser or client; this command does not expose Keep publicly or change host networking.

## Selecting an existing required-jail helper

An operator with the qualified Bubblewrap0.13.0 helper in a protected root-owned
installation can add these options to the same init command:

```sh
  --test-namespace-jail=required \
  --test-jail-executable=/absolute/protected/keep/bwrap
```

Initialization saves these settings in the private instance profile and inspects
the required helper's fixed bytes and protected ownership without executing it.
Missing or untrusted helpers refuse with the corrective options. No global installation, `/opt`
mount or host-policy change is performed. Omit the path to select the existing
`/opt/keep/bubblewrap/0.13.0/bwrap` default. A selected path requires required mode;
it cannot silently enable a best-effort fallback. The other explicit modes are
`--test-namespace-jail=best-effort` and `--test-namespace-jail=off`. Existing
`KEEP_TEST_NAMESPACE_JAIL` and `KEEP_TEST_JAIL_EXECUTABLE` selections remain supported.

With the ordinary project settings configured, `keep doctor` reports missing or
untrusted helper prerequisites without a model call. A trusted-helper result
does not prove namespace enforcement or generation readiness: actual repository
checks must report their setup result. Existing host namespace permissions are
still required. See [the execution boundary](../SECURITY.md#opt-in-required-project-boundary-experimental).
