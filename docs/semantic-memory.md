# Semantic memory encoder configuration

Keep can combine lexical retrieval with an independently configured embedding
endpoint in native project work. It needs no embedding SDK or new dependency.
The endpoint must implement the OpenAI-compatible embeddings protocol. Existing
chat-only installations continue to work without an encoder.

Revision, dimension and role prefixes are operator declarations, not verified model
weights. Configure them to match the endpoint's actual model. Prefixes are literal:
spaces and empty prefixes matter; Keep does not infer vendor-specific input types.

## Configure the encoder

For example, using an endpoint you already operate (the model name below is a
placeholder, not a recommendation or a download instruction):

```sh
keep encoder configure --profile=/absolute/path/encoder.json \
  --name=memory-encoder --authority=owner --location=local \
  --endpoint=http://127.0.0.1:9000/v1 --model=YOUR_ENCODER \
  --revision=YOUR_MODEL_REVISION --dimension=1024 \
  '--query-prefix=QUERY: ' '--document-prefix=DOCUMENT: ' \
  --query-purpose=memory-query --document-purpose=memory-document --region=local \
  --requests=128 --input-bytes=8388608 --windows=4096 --credential=environment
export KEEP_ENCODER_PROFILE=/absolute/path/encoder.json
keep encoder show
keep doctor
```

Supply the encoder's credential in `KEEP_ENCODER_API_KEY` through your existing
secret-management mechanism. Chat's `KEEP_PROVIDER_API_KEY` is never inherited.
Alternatively select `--credential=file --credential-file=/absolute/protected/key`
or `--credential=stdin`. Chat and encoder cannot both read the same stdin stream.
Only owner/local canonical loopback endpoints may use `--credential=none`.
Profiles are bounded mode-0600 JSON and contain references, not credential values.
There is no implicit encoder profile discovery: `KEEP_ENCODER_PROFILE` selects it.
Edit the JSON if query/document processing requires distinct regions.

The example limits are explicit per-original-job resource ceilings, not a price
quote or recommended capacity. Requests, complete serialized input bytes and input
windows are reserved for worst-case retries before dispatch. Restarting does not
renew the budget. Unknown effects hold for reconciliation, not blind retry.
Choose finite limits for your corpus and endpoint. Dollar-cost metering and larger
corpus qualification are separate outstanding obligations.

## Authorize retrieval and disclosure

Configuring an encoder does not authorize document egress. An ordinary project
command needs both the selected memory scope and semantic opt-in:

```sh
keep project 'Repair the retry behavior' --project=PROJECT_ID \
  --memory=user --memory-processing=configured-provider \
  --memory-semantic=configured-encoder
```

Replace `PROJECT_ID` with the existing project ID. The memory flags above are
explicit permission to send eligible source windows to the encoder.
Scope, principal, currentness, consent and erasure filters apply before encoding.
The planner retains exact source citations. Job-local vectors are ephemeral and
not written into memory snapshots. Configuration changes and changed consumed
sources invalidate the old planning context; they do not silently refresh a plan.

### Time and source identity

Task-memory quotes present `recordedAt`, `validFrom`, `validTo` and `useUntil` as
UTC date strings (or labeled epoch milliseconds for unusual legacy values), with
absent bounds remaining null. Storage and currentness checks remain numeric.
Record/ingestion time is not necessarily the event time described in source text.
This formatting does not exempt the quote or its private text from privacy checks.

### Ephemeral vectors and privacy mappings

The ordinary semantic path uses one temporary private-entity mapping per task:
the same detected category/exact value gets the same substitute in documents and
queries, with unrelated substitutes in other tasks. Mapping identity is bound to
the job-local vectors; mappings are not persisted or logged. Missing or mismatched
transformation identity refuses encoding. Legacy per-call chat privacy is unchanged.
This exposes equality within the selected corpus and does not guarantee anonymity,
complete PII detection, or unchanged retrieval quality. The current detector can
miss unstructured or window-spanning identifiers; aliases are not resolved.
Lexical memory remains available without semantic opt-in. Learned quality,
persisted derived views and larger-corpus capacity still require qualification.

## Optional exact private-source retention

Ordinary memory ingestion still sanitizes detected private identifiers. To retain
exact private facts, the installation operator must explicitly configure permitted
retention purposes; the writer must independently have scope access, initialized
retention consent and explicit per-command intent. This is separate from model
disclosure permission and does not require an encoder.

```sh
keep memory-retention configure --profile=/absolute/path/retention.json \
  --authority=owner --purposes=project-context --max-use-ms=86400000
export KEEP_MEMORY_RETENTION_PROFILE=/absolute/path/retention.json
```

Restart the Keep gateway/worker with that environment to apply the protected
mode-0600 profile. For organization installations, use `--authority=organization`;
the installed identity configuration and authenticated tenant scope still control
access. An ordinary user with `memory.write` need not be a configuration admin.
The policy file cannot authenticate a tenant or grant a user's permissions.

After selecting an appropriate absolute epoch-millisecond deadline within that
policy's limit, the ordinary client can use:

```sh
keep memory init --scope=user --retain
keep memory store 'Contact retained.contact@example.test' --scope=user --durable \
  --private-purpose=project-context --use-until=YOUR_EPOCH_MS_DEADLINE
```

The configured duration above is an example, not a recommended legal retention
period. `--max-use-ms=unlimited` permits an omitted use deadline; choose that only
when appropriate to the information and your obligations. The JSON policy can
specify different limits for different purpose IDs. `keep doctor` inspects the
selected profile without model calls.

Accepted private sources preserve their exact text in existing encrypted custody,
including email/SSN values, with their purpose, policy digest and deadline. They
create no ingestion embedding or original-text sidecar. Detected secrets and
disallowed-license content refuse the entire private write instead of silently
changing it; detection is heuristic and cannot guarantee every secret is found.
The receipt distinguishes exact private retention from sanitized ingestion.
Correcting a private source requires an explicit `--private-purpose` again; omitted
intent or a rejected replacement leaves the predecessor intact.

### Policy changes and erasure

After restart, the current policy governs recall, review, list, task context and
derived views through their source lineage. Removing the policy or a purpose,
tightening its duration beyond an existing source's lifetime, or reaching the use
deadline withholds affected content, including previously recorded recall results.
Changing the file does not hot-reload running processes. Withholding is not erasure:
use the existing explicit erase/hold controls, and account separately for backups,
caller copies and provider copies. Old sanitized text cannot be reconstructed.

Semantic use still requires the per-command disclosure flags above and applicable
organization egress policy. Matching private-entity substitutes are applied to
document/query encoding, not used as a substitute for retention authorization.
These controls support auditability; they are not legal-compliance certification
or a determination that consent alone supplies a lawful basis.

## Organization deployments

Use `--authority=organization` and provide `--release-bundle=/absolute/encoder.cbor`
and `--release-trust-root=/absolute/encoder-root.cbor`. The ordinary chat profile
must already select organization authority and its identity/policy references.
The encoder requires its own exact installed-release admission for its descriptor;
a chat admission token cannot be reused for it. No closure format is widened.

The existing organization residency policy must independently permit the encoder
host, query purpose, document purpose and respective regions. Encoder configuration
does not add permissions to that policy. Optional `--providers=ProviderA,ProviderB`
is a separate external route allowlist with fallback disabled, data collection
denied and zero-data-retention requested; it is not proof of provider compliance.
`doctor` checks chat and encoder release admission separately, without network calls.
