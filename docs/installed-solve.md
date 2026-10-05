# A configured repository goal with solve

Keep **0.0.12-preview.1** includes installed solve through the project runtime. First try `keep demo project` for the scripted walkthrough, then configure an actual provider and your own repository as below.

Configure the provider using the existing provider profile/environment contract. Repository work also requires KEEP_REPOSITORY, KEEP_WORKSPACE_BASE (separate from the source), KEEP_REVISION (exact commit), KEEP_REPO_REF, KEEP_BASE_BRANCH (defaults to main, must point at that commit), and KEEP_TEST_COMMAND with optional KEEP_TEST_ARGS_JSON. Run `keep doctor` first; its readiness result is configuration evidence, not a model-quality or production-host qualification. `keep onboard` captures directives; it does not configure these execution settings.

The automated solver requires a model price known to its existing accounting path. An unknown remote-compatible model price refuses before wire, including for a loopback endpoint; locality does not imply a zero fee. A readiness result does not establish current prices or funded execution. This ticket preserves that gate and its existing diagnostic limits.

```sh
keep solve "Correct the retry limit; preserve unrelated behavior and tests"
```

Solve accepts a description and no options. It starts with approval required, including when KEEP_PROJECT_POSTURE is autonomous. The printed run and decision identify the next operation:

```sh
keep project resume <run-id> --approve=<decision-id>
```

Keep materializes the exact source revision into a workspace. The runtime records the change proposal, diff/rollback information and test results; follow its printed controls. Pending project work uses project resume/merge controls, rather than the injected legacy solver's `keep review` queue. A merge decision is bound to the exact proposal digest:

```sh
keep merge <run-id> approve --proposal=<sha256>
keep merge <run-id> veto --proposal=<sha256>
```

A decision does not grant missing merge authority. Inspect a refused or held result; do not treat exit success for a recorded decision as proof that source changes landed. The original repository remains unchanged while a proposal awaits a decision. Existing owner-token checks and organization session/roster/custody restrictions apply; remote gateway solve uses the same authenticated project endpoint.

IS001 acceptance uses an installed package and a controlled loopback model endpoint. It establishes command routing, approval, a useful test-fixture edit and review/restart behavior. It does not establish real-model success rates, production isolation, live organization onboarding or a newly qualified release archive.
