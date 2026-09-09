# Security experiments with Keep

Selected research plans · September 10, 2026

How can we give agents more useful responsibility without putting people and their
systems at unnecessary risk? Keep provides a working setting for investigating
that question: agents can propose repository changes, consult persistent knowledge,
reuse procedures, and operate under explicit authority and acceptance rules.

The three studies below connect those mechanisms to practical security problems.
They are proposed comparisons, not completed experiments or demonstrated advantages.
Detailed protocols, model choices, budgets, and evaluation sets remain to be fixed
before execution. They complement the wider [research portfolio](research.md).

## 1. Security repairs that remain correct through acceptance and release

A plausible patch is only the beginning of a security repair. The patch must remove
the vulnerable behavior, preserve legitimate functionality, and remain the same
artifact that was checked when it is accepted and distributed. We propose studying
whether verification tied to the candidate and its delivery state reduces incorrect
acceptance at a useful cost. Keep's native proposal loop, separate work areas, and
governed merge/revert workflow provide the starting implementation. Historical
installed repository journeys supply bounded preliminary evidence; they do not
establish general vulnerability-repair performance.

The study would compare a competent coding agent with worktrees and conventional
tests, the same model with stronger independent security/behavioral checks, and
Keep's governed workflow. All methods would receive matched task information,
permissions, model access, and resource budgets. Comparisons using identical checks
would distinguish the value of the workflow from the value of additional evidence.
Tasks would use isolated, authorized repositories with reproducible failures and
benign controls; selected existing benchmark cases could be adapted after checking
their requirements and terms. Controlled changes between checking, acceptance, and
packaging would test whether evidence still applies to what is delivered.

Measurements would include vulnerability removal, functional regressions, incorrect
acceptance, checked-versus-delivered artifact mismatches, and total cost per correct
repair. Separately controlled checks would inspect the resulting code and behavior,
not accept a model's success statement. Proposed outputs are a task collection,
evaluation runner, and result bundles that other maintainers could use to evaluate
their repair workflows. Benchmark integration and these public bundles still need
development; they are not an existing standalone Keep service.

Related work includes [SEC-bench](https://github.com/SEC-bench/SEC-bench) and
[ContraFix v2](https://arxiv.org/html/2605.17450v2), which already investigate
security repair and runtime evidence. The proposed contribution must be established
against such methods, rather than inferred from combining agents and tests.

Starting points: [native proposals](../src/solve/edit_planner.ts),
[governed merge](../src/solve/governed_local_merge.ts), and
[repository evidence](evidence.md#native-repository-repair).

## 2. Useful skills whose approval survives the right changes

A reusable skill can improve a task while also carrying unnecessary permissions or
assumptions from its original environment. Its evaluation can become irrelevant
when its contents, dependencies, task scope, or permissions change. We propose
studying receiver-side qualification across this lifecycle: what evidence should
permit a particular version to be used, and when should it be reevaluated or retired?
Keep already has skill intake, comparative evaluation, and registry mechanisms.
Foreign-skill intake currently produces a replacement specification; completing and
testing the executable replacement path is part of the proposed work.

Comparisons would include no imported skill, direct generation from a trusted user
task specification, conventional scanning/signing/sandboxing/testing, and
task-conditioned privilege restriction. Keep's candidate approach would receive the
same information and execution limits. Equivalent useful tasks would have benign,
excessive-permission, and controlled adversarial skill variants. Tests would also
change content or authority after an earlier successful evaluation and compare live
eligibility with eligibility after restart. The trusted task specification, not the
imported skill's own description of intent, would define permitted behavior.

Measurements would include held-out task success, actual prohibited effects,
unnecessary rejection, lost functionality after scope reduction, and the costs of
generation, qualification, repair, and execution. Proposed outputs are a lifecycle
test collection, reference checks, and a comparison report for skill maintainers
and agent-framework developers. Adapters and documentation would be needed to use
these checks without adopting Keep. Structural validity, signatures, sampled
execution success, and comparative usefulness would remain separate results.

[NVIDIA's skill trust pipeline](https://docs.nvidia.com/skills/agent-skill-trust-pipeline)
already combines scanning, live evaluation, and signing;
[SkillScope](https://arxiv.org/abs/2605.05868) examines task-conditioned least
privilege. This study would investigate continued qualification through changes,
not claim those individual ingredients as new.

Starting points: [skill evaluation](../src/loop/skill_evaluator.ts),
[registry lifecycle](../src/registry/skill_registry.ts), and
[evidence boundaries](evidence.md#reading-implementation-claims).

## 3. Recovering useful work after poisoned or revoked memory

Removing an untrusted memory record does not by itself undo a plan or artifact
already derived from it. Restarting everything can avoid some reuse but discard
valuable work. We propose testing which work needs to stop or be recomputed after
information is corrected, identified as malicious, or made inaccessible, and which
unaffected work can safely continue. Keep's source-linked context, eligibility and
currentness checks, and historical corrected-memory coding tasks provide a starting
point. Broader repair across derived state and execution routes remains an open
research and engineering question.

The study would compare deletion-only memory, full task restart, version-aware
retrieval/history, and Keep's currentness-based approach, with selective replay
included where its assumptions and implementation apply. All methods would receive
the same source versions and authority-change information. Longitudinal repository
or administrative tasks would contain synthetic malicious material, legitimate
corrections, and access withdrawals introduced at specified stages. Independently
controlled repositories or local effect services would expose downstream behavior.

Measurements would include unauthorized downstream effects, later task correctness,
unnecessary interruptions, retained useful work, and retrieval/recomputation cost.
The proposed public output is a task-stream collection, effect checks, and a report
that helps developers choose a recovery policy. A portable runner and broader
model-backed comparisons still need development. The study concerns observable
execution behavior; it would not claim to erase information from model weights or
infer internal causal reliance from a citation.

Close comparisons include [MemSecBench](https://arxiv.org/abs/2607.27080) and
[Forgetting Without Restarting](https://arxiv.org/abs/2609.04875). Each protocol
would pin the relevant versions and respect their stated assumptions when testing
whether an approach transfers to Keep's deployment and authority conditions.

Starting points: [task memory](../src/memory/task_context.ts) and
[historical corrected-memory evidence](evidence.md#coding-with-corrected-memory).

## Evaluation and public outputs

Each study would fix its hypothesis, task distribution, threat model, comparison
implementations, outcome checks, and resource budget before the main evaluation.
Development fixtures and published answers would be recorded as exposed material,
separate from held-out evaluation tasks. Repetitions would isolate accumulated state;
reports would retain failures, unresolved cases, costs, and settings where simpler
methods suffice. Outside administration would be identified only when it occurs.

The intended publication set includes cleared task definitions, configurations,
inputs, model outputs or permitted excerpts, code changes, outcome checks, usage,
artifact identities, and summary results. Specific datasets, release timing, and
licenses remain subject to owner approval, applicable data/model terms, and
responsible disclosure. Sensitive vulnerabilities and private operational records
would not be published as demonstration material.

The current preview is an experimental foundation, not a ready-made runner for
these studies. Audit remediation and qualification of each consumed execution,
identity, isolation, and spending boundary precede relevant experiments. Use
synthetic data and isolated test resources; do not connect production credentials.
See [Security](../SECURITY.md), [existing evidence](evidence.md), and the
[no-key introductory demonstration](research-preview.md).
