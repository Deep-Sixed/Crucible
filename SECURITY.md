# Security Policy

Crucible is experimental and has not had a formal security audit. Its sandbox reduces the risk of evaluating agent-generated code, but it should not be treated as a complete security boundary. For high-risk or unknown code, also run Crucible inside a disposable VM.

Versions before the sandboxed attestation change in [PR #1](https://github.com/Deep-Sixed/Crucible/pull/1) can execute agent-controlled code on the host and must not be used with untrusted repositories.

## Reporting a vulnerability

Please do not report vulnerabilities in public issues. Use [GitHub private vulnerability reporting](https://github.com/Deep-Sixed/Crucible/security/advisories/new) and include the affected commit, impact, and a minimal reproduction. Remove credentials and private data from your report.

Security fixes are provided on the latest commit of `main`.
