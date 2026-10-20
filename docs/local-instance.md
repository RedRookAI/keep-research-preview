# Start a local Keep instance

The development source adds `keep instance` to save setup and operate one local project worker. The qualified 0.0.12 download predates these commands. Use the current development build until a matching release is published.

## Save the setup

Choose an existing repository and the command that checks its behavior. For example, for a Node project whose checks run with `npm test`:

```sh
keep instance init /absolute/path/to/my-keep \
  --repository=/absolute/path/to/my-project \
  --test-command=npm --test-args='["test"]'
```

The instance directory must be new, outside the source repository, with an existing parent directory. Keep creates private `data/` and `workspaces/` directories there and saves an inert `instance.json` profile. It captures the current branch's exact commit. Use `--branch=<existing-branch>` to select another branch. Advancing that branch requires deliberately reconciling the saved revision before a new startup; it does not silently change the source used by an existing project.

No API key, owner token or Codex authentication value is saved in the profile. For an already configured experimental [Codex project role](codex-project.md), init captures the supplied `KEEP_PROJECT_MODEL` and `KEEP_CODEX_*` settings. Startup still does not establish successful generation or complete native tool exclusion. Review the profile before enabling model work. Profile edits apply after stopping and restarting this owned instance; status distinguishes saved setup from the live dispatch state.

Without a project model, Keep starts its real gateway/worker with dispatch paused and the local deterministic stub selected. That mode lets you operate the instance without a model request; it is not live AI generation. Repository dependencies and the configured test command must be available in the eventual project workspace before useful repository work can pass.

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

The console lists retained native projects and opens their current stage, pending decision, jobs, activity, proposal diff and repository checks. Unavailable checks appear as unavailable. Approve or decline an exact pending step, or approve/veto the exact displayed proposal. The result distinguishes workspace changes from a recorded source landing; approval alone does not mean the source changed. Refresh shows the latest persisted state without starting or replaying work. The older review queue remains a separate surface for its existing consumers.

The console uses the same project APIs and authority checks as other clients, with Host, Origin and CSRF checks for browser actions. Organization deployments use their configured identity sessions; header-only custom principal resolvers do not fall back to owner browser access. The worker's dispatch remains paused until deliberately enabled through its existing controls. Signing in or opening a project never starts generation.

## Stop and reopen

```sh
keep instance stop /absolute/path/to/my-keep
keep instance status /absolute/path/to/my-keep
keep instance start /absolute/path/to/my-keep
```

Stop authenticates and checks the exact recorded worker identity. It requests shutdown through Keep's existing API, without signaling a saved PID or changing a service manager. A worker with active or queued work refuses shutdown; inspect or cancel that work through its normal controls first. State is retained across stop/start, and startup never resubmits a model request to prove readiness.

An existing live worker is reported instead of duplicated. If startup acknowledgement is lost, Keep retains `startup-pending.json` and refuses automatic relaunch. Inspect this instance's private diagnostic/lifecycle records to resolve its actual state. Do not remove another instance's records, reset project state or launch again under a new directory to evade uncertain work.

For a remote development box, the loopback address is local to that box. Use an SSH tunnel to reach it from your own browser or client; this command does not expose Keep publicly or change host networking.
