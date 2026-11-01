# Security policy

## Scope of this repository

This repository **tests** an intentionally vulnerable application (OWASP crAPI) on a local machine. The
vulnerabilities it documents in `docs/findings/` are crAPI's designed training vulnerabilities, reproduced
against `127.0.0.1` only. They are not vulnerabilities of any production system.

Rules for running anything here: [docs/rules-of-engagement.md](docs/rules-of-engagement.md). Never point
the scanners or tests at a host you do not own.

## Secrets

- No real secret is ever committed. Credentials in `stand/compose.yaml` are crAPI's public demo values;
  `stand/keys/jwks.json` is crAPI's public demo key set (needed to start the identity service).
- The Gitleaks demonstration uses a **fake** token format (`QAFAKE_…`) that cannot be confused with a real
  provider's token. The fake rule lives in `.gitleaks.toml`.
- Pre-commit runs ruff, mypy and a Gitleaks scan of staged changes.

## Reporting a problem with this repository

If you find a real secret or a way this repository could harm someone's system, open an issue without
the secret itself, or contact the owner through the GitHub profile. Findings about crAPI itself belong to
the [OWASP crAPI project](https://github.com/OWASP/crAPI).
