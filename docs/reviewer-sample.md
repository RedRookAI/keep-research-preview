# Host a controlled reviewer sample

The sample gives one assigned reviewer a separate instance and a prepared webhook task. Two authored responses produce a workspace fix and four executable checks. The reviewer chooses **Start demo**, then **Prepare the fix**, inspects the diff, approves or vetoes the proposal, and downloads evidence. Every sample page identifies the scripted responses. An AI account is unnecessary.

The current public demo is:

https://keep-demo.redrook.ai/console

The public demo opens without a credential. The default launcher below creates a private invitation; `--public` explicitly opens only the controlled sample. The [guided demo](guided-demo.md) shows the workflow.

## Prepare an instance

Each invitation needs its own process, new private root, credential and HTTPS origin. The launcher uses existing hosting and TLS configuration. It refuses an existing instance root.

Use a compiled checkout with Node and Git available. Supply the canonical HTTPS origin and optional private listener port; zero selects a free port:

```sh
node tools/reviewer_sample.mjs "$NEW_PRIVATE_ROOT" "$PUBLIC_ORIGIN" 0
```

The foreground process prints its private loopback address, public origin, source identity and credential-file location. A random `invitation-token` is written with mode `0600` inside the new `0700` root. Deliver its contents privately to the assigned reviewer. The token stays out of startup output and URLs.

Source, workspaces, state, HOME and TMP are separate for each instance. The child receives a minimal environment without model credentials. `createBrowserProjectFixture` fixes the repository, checker and two responses; HTTP requests cannot substitute paths, commands, memory scope, workflow, provider or credentials.

## Public sample

To remove the credential prompt from a disposable sample, pass `--public` before the root path:

```sh
node tools/reviewer_sample.mjs --public "$NEW_PRIVATE_ROOT" "$PUBLIC_ORIGIN" 0
```

This mode requires the controlled sample fixture and an explicit HTTPS origin. Opening the console creates a Secure, HttpOnly, host-only browser cookie. Starting and preparing the task still require deliberate form submissions. Host, Origin, CSRF and exact-proposal checks remain active; arbitrary goals, raw APIs, administration routes and cancellation are unavailable.

The hosted public instance runs as an unprivileged user in a read-only container. Its only writable state is a bounded temporary filesystem containing the sample. Working repositories, credentials, model accounts and the Docker socket are not mounted. Container CPU, memory, process and log limits contain public traffic. Each public instance retains one shared task and its result.

## Configure the authorized TLS terminator

Map the exact public HTTPS origin to the printed private listener. Preserve Host and browser Origin, which the app checks directly. Forwarded headers confer no authority. Keep the listener private and use a distinct origin/process/root/credential for another reviewer.

`publicBrowserOrigin` accepts a canonical HTTPS origin without userinfo, path, query or fragment; `handle.origin` stays the private listener. This option refuses organization identity, tenant, custom-principal, restricted-client and native-worker combinations. The native worker CLI keeps its local behavior.

Enable `reviewerSample:true` only on the controlled fixture. It admits the listed console/root-redirect routes. Raw bearer APIs, health/admin/worker/debug/auth endpoints, query-token entry and unknown console routes refuse even with the invitation. Sign-in retains Host/Origin, CSRF, exact-proposal and export checks, and sets a host-only Secure, HttpOnly, SameSite=Strict cookie.

## One retained sample

**Start demo** submits the fixed hidden goal. The server rejects arbitrary goals and extra fields. Accepted forms share one canonical submission identity: refresh, lost-response retry, double submission and a fresh form recover the same project/job. Approval resumes create their own retained jobs without another response pair.

The three frozen repository checks cover first, duplicate and distinct delivery IDs; a developer-authored goal assertion supplies the fourth check. The example remembers delivery IDs in one running in-memory state. Production webhook deduplication requires durable storage and broader delivery guarantees.

Cancellation, failure and uncertain effects remain visible. Inspect that retained state before the next action. After review, retain the export and decide whether to retire the instance.

## Stop and retain evidence

Send SIGINT or SIGTERM to the foreground launcher. It pauses new dispatch, closes the listener, retains state and reports unresolved jobs. In-flight work can finish under its original controls. Inspect the journal and process state before replacing an instance with unresolved effects.

The launcher preserves existing roots and cannot restart one. A replacement needs a separately authorized fresh root/credential after the old effects are reconciled. Stop only the owned instance.

Authored code runs under the best-effort process profile. Separate roots and credentials provide the demonstrated application boundary. Hostile same-user code needs a separately qualified stronger execution profile.

## Source verification and browser evidence

Focused loopback tests cover origins, Secure cookies, fixed admission, one submission, cross-instance refusal and launcher privacy. Public deployment also needs an actual HTTPS browser check with assigned credentials and two isolated instances.

With a compiled checkout and available Playwright driver/browser:

```sh
node acceptance/browser_project.mjs "$NEW_EVIDENCE_ROOT" "$PLAYWRIGHT_ENTRY" "$BROWSER_EXECUTABLE" --sample
```

The runner uses a private browser context with muted audio. It checks the actual results, exact veto/export and fresh-form recovery without added jobs or responses. `SAMPLE_CONTRACT` binds the goal, file bytes and check names for browser/appliance consumers.

Advanced panels retain IDs, records and the diff. Active work refreshes its GET state; pending decisions, paused/failed/uncertain work and completed results stay still for review.
