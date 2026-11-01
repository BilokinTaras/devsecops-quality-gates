# DevSecOps quality gates · OWASP crAPI

A layered security testing pipeline — secrets, SAST, SCA, SBOM, DAST and API security regression tests —
against OWASP crAPI running only on 127.0.0.1, with one typed quality gate that blocks on new High/Critical
findings and a baseline where every accepted risk has a reason, an owner and an expiry date.

_README v0 — the full version follows the scanner and regression-test stages._

## Quick start

Prerequisites: Docker with Compose v2, GNU Make, Python ≥ 3.12 with [uv](https://docs.astral.sh/uv/).
macOS: `brew install uv`.

```bash
uv sync --frozen --all-groups
make check          # lint, types, unit tests of the gate (coverage ≥ 90 %)
make stand-up       # crAPI v1.1.6, images pinned by digest, ports on 127.0.0.1 only
make seed           # idempotent test data: users A and B with vehicles, posts, orders
```

Read [docs/rules-of-engagement.md](docs/rules-of-engagement.md) before running any scanner.

## Decisions

- [ADR-001](docs/adr/ADR-001-crapi-target.md) — crAPI over Juice Shop, VAmPI, DVWA
- [ADR-002](docs/adr/ADR-002-crapi-stand.md) — how the stand is run (digests, loopback, canary, no chatbot)
- [ADR-003](docs/adr/ADR-003-gate-policy.md) — what the gate blocks

## Licence

MIT — [LICENSE](LICENSE). crAPI is © OWASP, Apache-2.0; it is used as published container images.
