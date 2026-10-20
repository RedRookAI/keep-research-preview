# Restricted OpenClaw client admission

Development work adds a personal client credential for Keep's required OpenClaw integration. The native OpenClaw plugin and its supported runtime package are separate integration work; this page describes the Keep side. This is not included in the qualified 0.0.12 download. Genuine installed Codex operation and complete native tool exclusion remain unqualified; see [Codex projects](codex-project.md).

## Issue a client

Use the same personal public-repository Codex configuration and `KEEP_DATA_DIR` as the intended Keep worker. Keep uses its existing local owner authority to issue a durable, expiring `change.solve` grant. The selected repository must remain at its pinned commit with a clean working tree. Keep's data, workspace and client credentials belong outside that source repository.

Create a private directory for the two new files. Replace the expiry placeholder with your chosen future ISO timestamp:

```sh
mkdir -m 700 /absolute/private/client-directory
keep openclaw-client issue \
  --profile=/absolute/private/client-directory/client.json \
  --token-file=/absolute/private/client-directory/client-token \
  --agent-id=my-openclaw \
  --expires-at=YOUR_FUTURE_ISO_TIMESTAMP
```

Keep refuses existing output files. The profile stores a credential hash, grant identity, expiry and exact project runtime binding. The token file contains the random client credential; neither file contains the owner bearer or Codex authentication. Keep prints file locations, never the credential value. Give the trusted plugin access only to the client token file and its own state. Its process must not have direct source-write authority or access to Keep owner/Codex credentials; a tool allowlist alone does not provide that isolation.

Set `KEEP_OPENCLAW_CLIENT_PROFILE` to the profile path before starting the same configured worker. A saved [local instance](local-instance.md) can retain that reference in its owner-controlled `instance.json`. Restart only that owned instance to apply the profile reference. The profile and durable grant are checked again on use; revocation does not require a worker restart. Organization deployments retain their separate identity admission and cannot use this personal profile as an owner fallback.

## Restricted operations

The client authenticates using its token in the standard `Authorization: Bearer` header. Its only authenticated operations are:

| Operation | Input | Result |
|---|---|---|
| `POST /project` | Exactly `goal` and `idempotencyKey` | Durable `projectId`, `jobId` and replay status. Keep forces background dispatch and approval-required posture against the configured repository. |
| `GET /project/jobs?jobId=…` | One original own-work job ID | Bounded job, wait, proposal/check, review and delivery summary. |
| `GET /project?runId=…` | The same original job/run ID | The same restricted summary. |

The idempotency key accepts 16–128 ASCII letters, digits, `.`, `_`, `:` and `-`. The server binds it to the authenticated client, grant and runtime. Identical input returns the existing job after a lost response or restart; changed input under the same key conflicts. The caller cannot select a repository, project, identity, memory context, domain, posture or privileged route. Other authenticated routes refuse this credential. An unauthenticated `/health` response carries liveness only.

The summary excludes session history, owner credentials, full audit records and unrelated jobs. It contains `job.state`, an optional hold reason, `run.status/stage/wait`, proposal availability/digest/check booleans, `review.vetoed/latestDecision/generationDecision` and recorded workspace/source/revert delivery status. Missing run/check observations remain null. Text reasons are capped at 4096 characters. A completed callback can still be waiting for human review; neither callback completion nor an available proposal establishes a source landing. Retain an outstanding submission while its outcome is unresolved.

## Human decisions and recovery

Open the same worker's [project console](local-instance.md#open-the-project-console). The owner sees the requesting agent, exact pending generation step, proposal diff, checks and decision history. Approving that step records the deciding human separately while preserving the original agent command and grant. The agent cannot approve, resume, merge or veto with its credential, even if it knows the decision ID.

Keep rechecks the original command, live grant, current human approval authority and configured source before generation. An expired/revoked grant, changed binding or source, declined/stale decision or absent original command prevents dispatch. Native preparation carries its live authority check across awaited work. Generation approval does not grant proposal landing; exact proposal review remains a separate human operation. A wrong proposal digest cannot create a durable veto.

To revoke locally, select the existing `KEEP_DATA_DIR` and run:

```sh
keep openclaw-client revoke --profile=/absolute/private/client-directory/client.json
```

Revocation needs the local owner authority, not a working Codex login or model request. It retains the token file for deliberate disposal and leaves historical jobs, decisions and invocation claims intact. A fresh credential, key, session or data directory must not be used to bypass uncertain work. Inspect retained state and resolve that uncertainty first.

The native client candidate is in [integrations/openclaw](../integrations/openclaw/README.md). Its private durable journal recovers the original submission after a lost response. The packaged SDK/catalog and isolated consumer passed the controlled OpenClaw 2026.10.5 / Node 24.22.0 workflow. That evidence uses scripted local generation; it does not qualify genuine Codex operation or the final combined download. [Observed scope](qualification/openclaw-2026-10-20.json).
