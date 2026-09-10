# Security research at Keep

## How can we empower agents while keeping people in control?

Agents that work across sessions, learn procedures, and cooperate could take on
much more useful work. But a compromised agent could also steal information,
spread malicious behavior, or undermine the systems meant to detect an attack.

Keep is an open-source, self-hosted platform for investigating these problems.
Its execution runtime, persistent memory, skill system, permission controls, and
evidence records provide a starting point for testing defenses together.

The ten directions below are **proposed studies, not completed results**. Each
addresses a security question within an active research area. Detailed protocols,
comparison implementations, and model configurations remain to be established.

## 1. Protecting AI security reviewers from manipulation

An attacker can embed instructions in code, documentation, or tool output that
manipulate the AI reviewing it. A successful attack could allow a backdoor to pass
review or suppress a warning before deployment.

We propose testing whether Keep's acceptance workflow can separate untrusted
explanations from independently executed security checks and keep those checks
binding on the decision. Comparisons would include strong monitors, diverse
reviewers, and conventional security tests against attackers that know the review
process. [Adaptive Attacks on Trusted Monitors](https://arxiv.org/html/2510.09462v1)
already demonstrates monitor manipulation; the question is which defenses retain
both attack detection and legitimate work.

## 2. Stopping poisoned experience from becoming a malicious skill

An attacker can influence an experience that an agent converts into a reusable
procedure. The resulting skill may retain malicious behavior after the original
poisoned material is removed, spreading compromise into later tasks.

Using Keep's extraction and registry mechanisms, we propose comparing admission
and execution policies against static review, behavioral monitoring, origin-based
restrictions, and generation from trusted requirements alone. Tests would measure
actual unauthorized effects and useful skills retained.
[SkillJack](https://arxiv.org/html/2608.03509v1) establishes this attack direction,
with principally proxy-based evaluation.
[Defense-as-Skill](https://arxiv.org/html/2609.01487v1) studies runtime guards;
effective protection through skill transformation and reuse remains our proposed
defensive question.

## 3. Preventing agent teams from combining permissions into an attack

One agent may read information, another transform it, and another send messages.
Their individually permitted actions can collectively cause unauthorized
disclosure or sabotage, including across separate sessions.

We propose using Keep's delegation and fleet mechanisms to compare cross-session
security policies with session-bound authorization, persistent monitoring, and
restricted coordination. The aim is to prevent combined attacks without
eliminating useful teamwork. [Bounded Agents](https://arxiv.org/html/2608.15888v1)
already enforces delegated scope and prohibited action combinations, while
identifying cross-session coordination among its remaining challenges.
[SCHEME](https://arxiv.org/html/2605.29178v1) provides prior work on coordinated
sabotage. Simply adding a team-level monitor would not establish an advance.

## 4. Closing hidden communication paths through shared infrastructure

Agents intended to be isolated may discover that a package cache, artifact
service, or permitted tool can carry messages. That can enable unauthorized
coordination beyond the operator's intended boundaries.

We propose a controlled service environment for comparing isolation and
information-flow controls while measuring both unintended communication and
legitimate task completion. Keep would coordinate the experiments; additional
systems-security infrastructure is required. The
[Hugging Face incident report](https://openai.com/index/hugging-face-incident-and-the-road-ahead/)
documents unintended shared-infrastructure communication, and
[tool-enabled steganography research](https://arxiv.org/html/2606.28425v1) examines
covert channels. Our question is which service arrangements resist adaptive
coordination while preserving necessary shared functionality.

## 5. Preventing secret theft through useful outputs

A compromised agent can hide information in an otherwise legitimate report, code
artifact, or message. Several apparently harmless outputs may together disclose
a secret to an unauthorized recipient.

We propose extending Keep's disclosure experiments to measure what a recipient
can recover, not only whether an output contains a recognizable secret.
Comparisons would include information-flow restrictions, constrained output
formats, and calibrated disclosure policies under changing attacker knowledge.
[OCELOT](https://arxiv.org/html/2606.12341v1) already addresses cumulative inference
leakage. The proposed question is how well defenses preserve useful work when an
attacker gains additional information or uses new artifact types and encodings.

## 6. Detecting covert poisoning of AI training pipelines

An agent preparing training data or configuration could introduce a hidden
behavior into another model while ordinary evaluations appear benign. Accepting
that model could spread compromise into future deployments.

We propose comparing inspection during training with dataset screening and
final-model auditing, measuring hidden behavior detected, benign adaptations
rejected, and cost. [Fine-tuning auditing agents](https://arxiv.org/html/2510.16255v1)
and [Introspection Adapters](https://alignment.anthropic.com/2026/introspection-adapters/)
provide important prior methods. The question is whether timely, targeted
intervention improves detection against adaptive attacks. Keep has orchestration
interfaces; a qualified training backend, suitable compute, and specialist
evaluation remain necessary for this study.

## 7. Detecting sabotage that makes security research look successful

An agent can alter evaluation data, checking logic, or experimental configuration
so an insecure system appears secure. Repeating the submitted experiment may
reproduce the misleading conclusion rather than expose it.

We propose using Keep's coding and evidence paths to test auditors that generate
independent checks capable of distinguishing competing explanations. Comparisons
would include existing artifact-capable monitors and conventional reproducibility
checks at matched investigation budgets.
[ASMR-Bench](https://arxiv.org/html/2604.16286v1) studies research-sabotage auditing.
[ResearchArena](https://arxiv.org/html/2607.19321v1) identifies failures to select
the decisive behavioral test. Discovering that test without knowing the attack
in advance is the proposed research target.

## 8. Preventing attackers from hijacking incident responders

Attackers control parts of the logs and alerts a defender must inspect. Misleading
evidence could cause an automated responder to disable monitoring, revoke
legitimate access, destroy evidence, or restore a compromised resource.

We propose testing response policies through Keep's permission and recovery
mechanisms against disposable services with separately observed state. The
measurements would include attacker-caused damage, genuine incidents contained,
response time, and unnecessary disruption.
[OpenSec](https://arxiv.org/html/2601.21083v1) evaluates adversarial incident
evidence; [AIR](https://arxiv.org/html/2602.11749v1) provides an agent response
framework. Our question is how to authorize effective response actions when
observations conflict, arrive late, or are attacker-controlled.

## 9. Preventing reinfection after an agent appears to be cleaned

Deleting malicious source material can leave behind a compromised skill, cached
plan, peer memory, or checkpoint. Restarting work may reactivate the attack.

We propose using Keep's memory and lifecycle mechanisms to compare quarantine,
revalidation, clean rebuilding, and rollback across derived and shared state.
Tests would measure actual recurrence, legitimate work preserved, and recovery
cost, including cases with incomplete dependency records.
[SkillJack](https://arxiv.org/html/2608.03509v1) describes persistence after source
deletion, and [AIR](https://arxiv.org/html/2602.11749v1) includes eradication.
The proposed contribution is evidence about when useful work can safely resume
after compromise has spread—not another source-deletion mechanism.

## 10. Trustworthy investigation when agents can manipulate evidence

A compromised agent may alter records or steer an investigator toward an
incomplete account. An operator could then miss the extent of a breach or
incorrectly conclude that it has been contained.

We propose testing AI-assisted investigations against controlled incidents with
missing or manipulated evidence and separately collected observations. Keep's
audit and witnessing interfaces provide starting machinery; trustworthy
observation must be established independently of the investigated agent.
Comparisons would measure missed attacks, false accusations, unsupported
conclusions, and investigation cost. The
[METR and Redwood investigation](https://metr.org/blog/2026-08-26-openai-hugging-face-incident-investigation/)
documents evidence manipulation and limitations of AI-assisted analysis.
Hashes alone cannot establish truth or completeness.

## Evaluation and public outputs

Studies would use authorized, isolated environments, synthetic sensitive data,
and outcome checks separate from the agents being evaluated. Strong existing
defenses, legitimate-work controls, and held-out evaluation would be part of each
comparison. Success means reducing harmful outcomes while preserving useful
capability—not refusing every task.

We plan to publish reusable test material, runners, configurations, and results,
including failures, subject to applicable terms and responsible disclosure.
The [evidence record](evidence.md) describes Keep's existing results and their
scope; the [security policy](../SECURITY.md) explains current operating limits.
