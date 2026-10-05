# Inspect the repository walkthrough

Run `keep demo project` after installing the matching preview. It runs the actual installed solve/project/merge commands against a temporary sample repository. A controlled loopback endpoint supplies two authored responses: a retry-limit edit and a goal-test body. The walkthrough simulates approval and veto; it does not ask a live model or charge a provider.

The scenario starts with `retryLimit = 0` and a repository test expecting 7. Although the sample configuration says autonomous, solve requests approval-required. Before the sample approval, the model-call count is zero. After approval, Keep edits its separate working copy, runs the repository and goal tests, and produces a diff. Restart retains that proposal without repeating requests. A wrong token refuses; the final sample veto leaves the source at 0.

The command prints the diff and its own evidence directory:

| Artifact | What to inspect |
|---|---|
| `source/src/retry.mjs` | Original value remains 0 |
| `workspaces/project/src/retry.mjs` | Proposed value is 7 |
| `outcome.json` | Proposal diff, checks, goal-test result and process-isolation observation |
| `result.json` | Completed checks, exactly two controlled responses and simulated decisions |
| `command-*.json` | Actual command inputs, exits and output |
| `model-calls.json` | Synthetic prompts delivered to the local fixture |

These are local sample records, not provider bills or independently attested evidence. The default demonstration reports best-effort process isolation; it does not establish production containment. Passing the authored scenario does not establish performance on arbitrary repositories, real-model success rates or live organization identity/custody. Retain a failed run's evidence rather than claiming its checks passed.

No user repository, ordinary Keep state, API key or remote account is used. The demo needs Linux x64, Node/npm/Git and an available ephemeral loopback port. A missing Git prerequisite is reported before work; `keep demo recovery` offers a Git-free, account-free alternative. Closing or interrupting the demo stops its own process group, without stopping other Keep instances.

To try actual model-backed work, follow [configured solve](installed-solve.md). Give Keep one bounded repository goal, inspect its printed approval and proposal controls, and compare the resulting diff/tests against your intended outcome. Observations about setup clarity and useful results should inform later work; the scripted demo alone does not validate those broader outcomes.
