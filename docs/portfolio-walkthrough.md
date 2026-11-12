# Account-free repository walkthrough

Run `keep demo project` after [installing the matching preview](quickstart.md), or [watch the recording](portfolio-demo.md). The command uses Keep's installed solve/project/merge workflow against a temporary sample repository. Two authored responses supply a retry-limit edit and goal test; the fixture makes the sample approval and veto decisions. It needs no model account or paid calls.

The source starts at `retryLimit = 0`, with a repository test expecting 7. The solve command requires approval even though the sample configuration says autonomous. Before approval, the response count is zero. Keep then edits a separate workspace, runs the repository and goal tests, and produces a diff. Restart retains the proposal without repeating requests. A wrong token is refused; veto leaves the source at 0.

The command prints the diff and its evidence directory:

| Artifact | What to inspect |
|---|---|
| `source/src/retry.mjs` | Original value remains 0 |
| `workspaces/project/src/retry.mjs` | Proposed value is 7 |
| `outcome.json` | Diff, checks, goal-test result and process-isolation observation |
| `result.json` | Completed checks, two authored responses and sample decisions |
| `command-*.json` | Command inputs, exits and output |
| `model-calls.json` | Prompts delivered to the local fixture |

The demo needs Linux x64, the supported Node 22 runtime, Git and an available ephemeral loopback port. It uses its own repository and state. The [direct archive route](combined-preview.md) runs without npm installation. Missing Git is reported before work; `keep demo recovery` provides a Git-free alternative. Interrupting the demo stops its own process group.

The fixture reports best-effort process isolation. Its records describe this synthetic run; retain the evidence if a check fails. See [security boundaries](../SECURITY.md) for repository execution requirements.

For model-backed work, follow [configured solve](installed-solve.md). The [recorded Codex/OpenClaw case](genuine-codex-walkthrough.md) shows one completed live-generation result.
