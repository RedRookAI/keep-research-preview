# Controlled reviewer sample

The foreground sample gives one assigned reviewer a separate Keep instance with a fixed repository task. Two authored provider responses produce a real workspace edit and executable checks. The reviewer submits the goal, approves the pending step, inspects the diff, approves or vetoes the exact proposal, and downloads retained evidence. Every console page identifies the scripted sample. No AI account or paid provider is used.

Each invitation needs its own process, new private root, credential and HTTPS origin. These are operator-assigned instances. The launcher does not allocate visitors or create hosting, DNS, certificates or services.

The deployed Red Rook invitations passed actual public HTTPS browser qualification on November 12, 2026. Ask the operator for the credential assigned to your instance, then open its sign-in page:

https://keep.redrook.ai/console

https://keep-b.redrook.ai/console

The qualification report and exact source/profile receipts are in `qualification/reviewer-handover-2026-11-12.md`. This sample demonstrates the real workflow with scripted responses; personal live-account setup is a separate path.

## Prepare an instance

Use a compiled checkout with Node and Git already available. The launcher refuses an existing instance root. Supply the operator-selected canonical HTTPS origin and an optional private listener port; zero selects an available port.

```sh
node tools/reviewer_sample.mjs "$NEW_PRIVATE_ROOT" "$PUBLIC_ORIGIN" 0
```

The process stays in the foreground. It prints the private loopback listener, configured public origin, source identity and private credential-file location. It writes a fresh random credential to `invitation-token` with mode `0600`, inside a new `0700` instance root. Deliver that credential to the assigned reviewer separately. The credential never appears in a URL or startup output.

The child runtime has separate source, workspaces, state, HOME and TMP directories. It receives a minimal environment without inherited model credentials. Its source, checker and two scripted responses come from `createBrowserProjectFixture`; HTTP input cannot select another repository, command, memory scope, workflow, provider or credential.

## Configure the authorized TLS terminator

Map one exact public HTTPS origin to this instance's printed private loopback listener. Preserve the public Host and browser Origin. The app checks them directly and does not use Forwarded headers to establish authority. Keep the listener private and give the second reviewer a separate origin, process, root and credential.

The `publicBrowserOrigin` server option accepts a canonical HTTPS origin with no userinfo, path, query or fragment. `handle.origin` remains the actual private listener. This option refuses organization identity, tenant, custom-principal, restricted-client and native-worker combinations. The existing native worker CLI retains its local behavior.

Enable `reviewerSample:true` only on the controlled fixture app. This setting closes ingress to the listed console and root-redirect routes. Raw bearer APIs, health/admin/worker/debug/auth routes, query-token entry and unknown console routes refuse even with the invitation credential. Real console sign-in, Host/Origin, CSRF, exact decision and export checks remain in force. HTTPS sign-in sets a host-only Secure, HttpOnly, SameSite=Strict cookie.

## One retained sample

The goal form is prefilled and read-only. The server validates the exact sample goal and rejects additional submission fields. All accepted forms use one private canonical submission identity. A refresh, lost response, double submission or fresh form recovers the original project/job. It cannot start another pair of responses. Explicit approval resume jobs remain separate retained jobs.

Cancellation, failure or uncertain effects remain visible. The operator must inspect retained state before deciding what to do next. A new form does not reset the sample. After the reviewer finishes, retain the proposal export and decide whether to retire that instance.

## Stop and retain evidence

Send SIGINT or SIGTERM to the foreground launcher. It pauses new dispatch and closes its listener, retaining state and reporting any unresolved jobs. Existing in-flight process work can finish under its original controls. A stopped listener is not proof that every external effect settled. Inspect the retained journal and process state before an explicit operator reset.

The launcher never deletes or replaces an instance and cannot restart an existing root. Startup failure or interrupted work requires operator inspection. A replacement invitation uses a separately authorized fresh root and credential after the old instance's effects are reconciled. Stop/reset only the owned instance; leave other slots and shared services alone.

The sample uses the existing best-effort process execution profile for authored code. Separate roots and credentials establish the demonstrated application boundary; they do not establish production isolation against hostile same-user code. A deployment requiring stronger isolation must qualify that profile separately and retain its refusal behavior.

## Source verification and browser evidence

Focused source tests simulate TLS-terminator headers over loopback and check origins, Secure cookies, fixed admission, one logical submission, cross-instance refusal and private launcher state. Those checks do not establish real hosted HTTPS.

The existing browser runner accepts an optional final `--sample` flag. With an already installed Playwright driver/browser and compiled source:

```sh
node acceptance/browser_project.mjs "$NEW_EVIDENCE_ROOT" "$PLAYWRIGHT_ENTRY" "$BROWSER_EXECUTABLE" --sample
```

It drives the enforced sample using a private browser profile with muted audio, verifies the real checks and exact veto/export, and confirms that a fresh form adds no job or provider calls. Public deployment needs its own actual HTTPS browser qualification with assigned credentials, correct routing and two isolated reviewer instances.
