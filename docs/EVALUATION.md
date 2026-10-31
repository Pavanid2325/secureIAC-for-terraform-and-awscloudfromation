# Reproducible evaluation

The intended contribution is comparing independently retained deterministic
findings with retrieval-grounded, evidence-validated contextual concerns and
organization policies. This repository is an experimental implementation, not
proof of accuracy, cost advantage, functional equivalence or publishability.

`requirements-tested.txt` records the core/dev/OAuth packages used for the Windows
Python 3.12 offline verification. Install it with `python -m pip install -r
requirements-tested.txt`, followed by `python -m pip install -e . --no-deps`.
Optional scanner, semantic-model and UI environments still need their own tested
locks and model revisions before a reproducible live study.

`evaluation/starter.json` records version, case ID, group, split, template path,
label review status and expected identities. Cases cover insecure/safer
configurations, policy violations, cross-resource references, unresolved conditions
and prompt injection. `examples/rds-encryption-patch.json` is a remediation case.
All labels are **pending_human_review**, including nominally secure examples;
their names do not establish ground truth.

```powershell
# No cloud inference; missing Checkov is reported as partial
python -m src.evaluation --variant scanner-only
# Offline mock orchestration; metrics remain null
$env:LLM_PROVIDER = "mock"
python -m src.evaluation --variant llm-only --output reports/demo-evaluation.json
# After configuring embeddings, policies and an explicitly enabled provider:
python -m src.evaluation --variant full --output reports/full-evaluation.json
python -m src.evaluation --variant full --no-policies --no-relationships --output reports/ablation.json
```

Supported comparisons: scanner-only, llm-only, llm-rag, scanner-llm-rag and full.
RAG is ablated using `--no-rag`; policies and relationship summary have switches.
`--no-relationships` removes the explicit relationship map, not references in the
raw template; it is not a claim of fully removing relational information.

Before scoring, independently review expected findings for every variant and
set `label_status` to `human_reviewed`. Provide `title_categories` mappings for
LLM titles, or adjudicate unmapped titles; these mappings must be frozen before
test runs. Matching is exact `(resource identity, check/policy/category)` set
matching; duplicates count once. Scanner check IDs and policy IDs are distinct.
Do not interpret a scanner's unreviewed full finding set as false positives.

The harness computes precision, recall, F1 and false-positive counts for completed
non-demo runs with reviewed labels. Failures and partial results remain in the
denominator/counts for operational reporting rather than disappearing. It records
invalid-output rate, latency, available provider usage, exact model, prompt/schema,
policy/corpus/scanner and dataset hashes. Related variants must share a split;
the starter set is all test and is too small for research conclusions.

Evidence correctness and remediation validity are null until independently
annotated, not assumed successful from application checks. Record a post-run JSON
list with `evidence_correct` and `remediation_valid` booleans (or null when not
reviewed); retain case/finding IDs and reviewer identity alongside these fields.
`python -m src.evaluation --review reports/review.json` aggregates the reviewed
rates and counts without inference. Keep those annotations tied to the exact run.
Use candidate `.validation.json` files to review parsing/lint/scanner/policy
outcomes, and separately assess behavior risks. The harness does not yet automate
remediation trials or inter-rater agreement. Record reviewers, adjudication rules,
tool/model versions, dependency lock and raw failure counts before publication.
