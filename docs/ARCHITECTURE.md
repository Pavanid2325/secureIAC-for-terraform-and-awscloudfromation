# Architecture and contracts

The parser preserves original CloudFormation values; normalization supplies
resource/relationship context. Three logical agents perform retrieval, contextual
detection and deterministic reporting. `scanning.py`, `policies.py`, and
`remediation.py` are modules, not autonomous agents.

`LLMClient.generate(trusted_instructions, prepared_context)` returns a
`ProviderResult` with candidate JSON, provider, exact returned model, request ID,
usage, completion status and timing. The detection agent owns the total retry
budget (1–5 attempts). SDK retries are disabled for OpenAI; Bedrock SDK retries are
disabled and its factory-configured adapter makes one attempt. Transient failures
can retry; refusals, quota/authentication errors, incomplete responses and input
budget violations cannot. One repair attempt consumes the same total budget.

The runtime v2 wire schema lives in `src/models/findings_schema.py`. Application
validation enforces resource identity, citation membership and JSON Pointer
evidence against original data. Legacy direct validation calls without raw data
remain for compatibility, but the analysis workflow always requires v2 evidence.
Source locations are null unless supplied by a scanner. Conditional/intrinsic
evidence must be classified as insufficient information. This does not validate
every natural-language implication of model prose.

Scanner results and organization-policy outcomes are stored independently in
analysis metadata and rendered in separate report sections. LLM output cannot
remove them. `complete` means requested stages completed, `partial` means a
requested scanner was missing/failed, and `failed` means contextual output failed.
Stages not requested are explicit. Demo output is labeled and cannot be scored.

Local semantic retrieval uses Sentence Transformers with cached models only.
Resource filtering retains generic chunks and matching resource types. Ranking
is 70% cosine similarity plus 30% exact token overlap. Ingest replaces the local
JSON index and records a content-based corpus hash, embedding model/dimensions,
and chunker settings. Legacy/mismatched indexes require reingestion. There is no
URL fetching from templates or model output and no sensitive response cache.

Security limits: input bytes, YAML/JSON depth/nodes, context bytes, output bytes,
API timeout, scanner timeout and scanner output bytes are bounded. Byte limits
are conservative application bounds, not exact tokenizer-based model context
limits. Subscription streaming has a local consumption cap, not a server token
cap. Local scanner processes receive a minimal environment and isolated temporary
working directory, but OS filesystem/network isolation remains a hosting task.

Remediation accepts a user-supplied patch and exact property allowlist. It produces
new JSON, structural diff and validation results; it never deploys. Lint/scanner
success and unchanged resource identities do not establish behavioral equivalence.
