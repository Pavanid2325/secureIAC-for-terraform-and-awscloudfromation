# Implementation record

Baseline (2026-10-10): clean working tree; no applicable AGENTS.md found.
24 existing offline tests pass (Windows pytest temp access required elevation).
Implemented before this work: CloudFormation safe loading, normalization,
relationships, local JSON store, hash/Titan embeddings, Bedrock detection,
schema/resource/citation checks, Markdown reporting and four CLI commands.
Missing: property evidence validation, semantic local embeddings, independent
providers, deterministic scanning, policies, candidate checks, UI, evaluation.
Terraform parsing is not implemented. Existing .env is not read or modified.

Execution order:
1. Provider contract, OpenAI Responses adapter, strict evidence schema and tests.
2. Scanner/policy modules and explicit analysis coverage; local semantic retrieval.
3. Separate candidate validation, local UI, evaluation fixtures and harness.
4. Documentation, offline regressions and final limitations audit.

No paid inference or publishing is authorized. Subscription eligibility cannot
be inferred from having ChatGPT Pro. Track unfinished features explicitly here.

## Implemented in this change

- Provider contract, explicit factory, official OpenAI Responses adapter, mock
  mode and optional Bedrock adapter; AWS imports are absent from the local path.
- Version-2 structured findings and checked property evidence, bounded attempts,
  refusal/quota/incomplete handling, sanitized failures and usage metadata.
- Experimental local SIWC OAuth with PKCE/state/nonce/JWKS validation, account
  selection, protected vault storage, serialized refresh and logout; completed
  streaming responses only. Actual account eligibility is unverified.
- Checkov/cfn-lint process adapters; separately retained scanner/policy outcomes;
  six example policy types, exceptions and unknown values.
- Cached local semantic embedding adapter, hybrid ranking and index manifest.
- Explicit allowlisted candidate-property patches with diff and validation record.
- Local Streamlit UI, offline-first evaluation harness, pending-review fixtures,
  manual-review metric aggregation, CI and expanded tests.
- README, configuration reference, architecture/evaluation/hosting documentation.

## Verification and remaining work

Baseline: 24 tests passed. Provider migration checkpoint: 38 tests passed before
broader features. Final test results are recorded in the handoff below.
An isolated `.venv` was created with core/dev/chatgpt dependencies; `pip check`
passes. Modern OpenAI SDK request/response behavior is tested with HTTPX mock
transport, not a paid call. CLI demo, deterministic policy analysis and seven-case
mock evaluation smoke runs complete. No template was deployed or input overwritten.

The optional UI/scanner/semantic dependency installation could not be completed
after a disk-space failure while downloading the UI stack. Core dependencies
installed successfully using `--no-cache-dir`; the optional UI test is skipped.
Real semantic-model/scanner executions and browser OAuth remain unverified.
No human-reviewed ground truth or accuracy claims were fabricated. Dataset review,
complete category mappings, automated remediation experiments and inter-rater
agreement remain research work. No project license was selected for the owner;
OSS eligibility and live SIWC use require confirmation before distribution.

## Handoff checks

Final isolated-environment suite: **61 passed, 1 skipped** (optional Streamlit
AppTest; Streamlit is not installed). The suite blocks network sockets and includes
official SDK mock transport, signed JWT checks, streaming failure handling,
credential-vault rotation, policy/scanner/candidate checks, evaluation and original
regressions. Python compileall, `pip check`, and `git diff --check` pass.
No real API inference, real OAuth sign-in, deployment, commit or publishing occurred.
The existing `.env` remains ignored and untouched.
