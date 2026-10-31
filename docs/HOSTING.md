# Local use and public-release requirements

Bind Streamlit to 127.0.0.1. Use one local operator, OS credential storage for
ChatGPT sessions, environment secrets for API mode and explicit live enablement.
The application sends template/normalized context, selected policy text and
retrieved guidance to the selected live provider. Reports and indexes can retain
sensitive configuration. CLI reports persist until the operator deletes them;
UI temporary files are removed after a run and in-memory results last for the
session. There is no application response cache.

A practical future host consists of an authenticated frontend, a job API and
isolated short-lived workers. Budget a small VM/container service plus bounded
worker capacity and provider usage; costs depend on workload. Do not assume free,
unlimited hosting or use the owner's ChatGPT subscription as a shared backend.
Remotely hosted/paid ChatGPT-plan use needs the applicable official integration
arrangement, not the local OSS flow assumed here.

Before public access implement and test:

- Authentication, per-user job ownership checks, per-user quotas and bounded concurrency.
- Scanner workers with restricted filesystem, no outbound network and CPU/memory/process limits.
- Upload size/type/parser-complexity checks at ingress and worker boundaries.
- Temporary-data retention/deletion, encrypted storage and explicit privacy information.
- Server-side secret handling and per-user credential isolation; no frontend API keys.
- Appropriate CSRF/CORS protections, secure sessions and deployment TLS.
- File access allowlists, path traversal defenses, SSRF prevention and no arbitrary URL fetching.
- Dependency pinning/update review, audit logging without raw prompts/secrets and incident handling.

None of these future hosting controls is implied by the local process wrapper.
No application was published as part of implementation.
