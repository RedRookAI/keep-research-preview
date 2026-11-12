# November 11 source update: tenant review and memory evidence

At this checkpoint, source was **0.0.22-preview.1** and the latest download was **0.0.21-preview.1**, with its separate frozen source and qualification.

Review reads and decisions now join the original tenant with the review ID. Tenant filtering precedes list, detail, decision, monitor and audit joins. Reusing an ID in another tenant cannot suppress or decide that tenant's review. Decisions retain the original human principal and existing permissions; an agent grant cannot supply human approval. Trusted intake obtains tenant metadata from the admitted runtime context. Personal reviews remain unlabelled.

Durable memory control events now carry canonical resource attribution from their established partition. Hold, erasure-request and terminal records appear in their own tenant's audit export. Recovery binds terminal evidence to the original committed actor before key revocation, including when a different recovery carrier completes it. Missing or ambiguous original evidence remains held. Existing historical records stay unchanged.

Source fixtures exercise authenticated two-tenant browser reads and decisions, reused IDs, role checks, agent refusal, sealed restart/export and zero foreign decision effects. Memory fixtures exercise actual authenticated controls/export, cross-tenant refusal, legitimate agent identity, personal unlabelled history and interrupted recovery in a fresh process. The review lane passed 128 affected checks plus one corrected producer check. A full configured-producer probe lacked its declared native package baseline; that failed probe is retained separately from the narrower passing producer control. The memory lane passed 21 selected controls, including existing persistence fault and gateway replay cases. Counts overlap other source observations.

Review covered tenant joins, resource attribution and original-actor recovery. Native binaries, builds and installed .21 observations retain their original subjects.

Integration exposed a compatibility regression: unscoped local-owner review audit had become personal-only, contradicting the retained full-trail requirement. The correction preserves that complete local read while explicit tenant views filter before ID joins. The regression fixture checks the complete four-record local trail alongside one-record alpha and two-record beta trails. Initial runs recorded 44/45 and 24/25; after correction, emitting compilation and **39/39** affected audit, review, workflow and CI checks passed with zero failures, skips or cancellations. Unchanged memory/export checks from the first integration remain applicable. Partial hosted CI now includes both new boundary files and the existing local-audit compatibility file.

This update does not complete the tenant platform. Full live project/memory recovery, current membership and installed enterprise acceptance remain open. Code-flow routes already held for missing session-effect checks stay held. A separate portability-export defect still needs an explicit trusted subject-selection contract: the default derived-memory mapper can relabel other subjects during bundle assembly. No authenticated HTTP portability route was found, and this update does not qualify that SDK export path. Global notification/calibration separation and historical attribution reconciliation also remain open.

The working downloadable checkpoint and its exact evidence:

https://github.com/RedRookAI/keep-research-preview/releases/tag/keep-preview-2026-11-11.2

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/qualification/combined-preview-2026-11-11.2.json
