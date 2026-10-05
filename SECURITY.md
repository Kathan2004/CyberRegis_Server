# Security Policy

## Reporting a vulnerability

Do not open a public issue. Report privately through GitHub:
**Security tab -> Report a vulnerability** on this repository.

Include the affected version or commit, reproduction steps, and the impact you observed.
You will get an acknowledgement within 72 hours, and a fix or mitigation plan within 14 days for confirmed issues.

## Scope

Code in this repository. Third-party services it integrates with are out of scope; report those to their vendors.

## Secrets

This repository must never contain credentials. Configuration is read from environment variables (see `.env.example`).
If you find a live credential in the code or history, report it as above.
