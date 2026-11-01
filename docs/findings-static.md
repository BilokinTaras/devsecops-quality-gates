# Triage of the static scans (2026-11-01)

Four tools, two targets: **this repository**, which the team owns, and **crAPI at v1.1.6**, a third-party
application that is vulnerable on purpose. What blocks a build and what is only reported is decided in
[ADR-003](adr/ADR-003-gate-policy.md).

| Tool | Version (pinned by digest) | Target | Result | Gate |
|---|---|---|---|---|
| Gitleaks | v8.30.1 | git history of 5 portfolio repositories (26 commits) | 0 leaks | blocking |
| Semgrep | 1.183.0 | this repository (32 files, 405 rules) | 0 findings | blocking |
| Trivy | 0.76.1 | this repository (dependencies, config, secrets) | 0 findings | blocking |
| Semgrep | 1.183.0 | crAPI source, 374 files | 54 findings | report |
| Trivy / Syft / Grype | 0.76.1 / v1.55.0 / v0.121.0 | 6 crAPI images | see below | report |

## Secrets (Gitleaks)

Full history of `devsecops-quality-gates`, `shop-sut`, `shop-e2e-playwright`, `shop-api-pytest` and
`shop-performance-k6`: **0 leaks**. Test credentials in these repositories live in `.env.example` files and
are documented as test-only, which is why they are not matched by the default rules.

The gate is demonstrated to fail on a planted fake token: [gate-demo.md](gate-demo.md).

## This repository (Semgrep, Trivy)

Semgrep with `p/python`, `p/security-audit`, `p/secrets`, `p/dockerfile` and `p/docker-compose`: **0 findings**
over 32 files. The default ignore list is replaced by `.semgrepignore` so test code is scanned as well.

Trivy over the repository reported nothing. Worth stating plainly: this repository contains **no file type
Trivy's misconfiguration scanner supports** (no Dockerfile, Kubernetes, Terraform or CloudFormation), and
`uv.lock` had no vulnerable package at the time of the scan. An empty result is "nothing to find here", not
"everything was checked".

## crAPI source (Semgrep, report only)

54 findings over 374 files. Grouped:

| Count | Rule | Service | Triage |
|---:|---|---|---|
| 36 | `request-host-used` | web | **False positive** for our purpose: Nginx/Lua config reading the request host; no fix applies to a target we do not own |
| 4 | `disabled-cert-validation` | workshop | **True positive**, CWE-295: `verify=False` on outbound HTTPS, including the call that performs FINDING-005 |
| 3 | `missing-user` | community, identity, web | **True positive**, CWE-250: container images run as root |
| 2 | `missing-ssl-minversion` | community | **True positive**, CWE-326 |
| 2 | `python-logger-credential-disclosure` | chatbot | Out of scope: the chatbot is not deployed on this stand (ADR-002) |
| 1 | `unverified-jwt-decode` | workshop | **True positive**, CWE-347 — the static counterpart of FINDING-001 |
| 1 | `jwt-go-parse-unverified` | community | **True positive**, CWE-347 — same class |
| 1 | `insecure-hostname-verifier` | identity | **True positive**, CWE-297 |
| 1 | `spring-csrf-disabled` | identity | True positive in general; low value for a token-authenticated API |
| 1 | `no-csrf-exempt` | workshop | Same |
| 1 | `math-random-used` | gateway-service | **True positive**, CWE-338, in a stub service |
| 1 | `avoid_app_run_with_bad_host` | chatbot | Out of scope |

**What SAST missed.** The SQL injection of FINDING-003 — `cursor.execute` with a concatenated request value
in `services/workshop/crapi/shop/views.py` — was **not** reported: zero rules matching `sql` fired across the
374 files. In the same file Semgrep flagged only line 141 (`verify=False`). The finding came from a manual
probe that sent a single quote and got a 500. This is the clearest argument in the project for keeping
manual testing next to the scanners.

## crAPI images (Trivy, Syft, Grype — report only)

Six service images, scanned from the registry by digest, `linux/amd64`. SBOMs in CycloneDX format are
produced by Syft and are the input Grype scans, so the two tools see the same inventory.

| Image | Tool | Critical | High | Medium | Low | Other | Critical with a fix |
|---|---|---:|---:|---:|---:|---:|---:|
| api.mypremiumdealership.com | Trivy | 9 | 107 | 190 | 132 | 8 | 8 |
| api.mypremiumdealership.com | Grype | 21 | 177 | 153 | 23 | 67 | 19 |
| crapi-community | Trivy | 3 | 79 | 108 | 63 | 7 | 3 |
| crapi-community | Grype | 36 | 152 | 118 | 21 | 7 | 26 |
| crapi-identity | Trivy | 14 | 60 | 532 | 167 | 0 | 14 |
| crapi-identity | Grype | 14 | 67 | 794 | 258 | 3 | 12 |
| crapi-web | Trivy | 2 | 57 | 85 | 64 | 6 | 2 |
| crapi-web | Grype | 33 | 165 | 134 | 29 | 7 | 23 |
| crapi-workshop | Trivy | 10 | 190 | 182 | 85 | 6 | 10 |
| crapi-workshop | Grype | 34 | 276 | 234 | 51 | 7 | 24 |
| mailhog | Trivy | 3 | 55 | 71 | 56 | 3 | 3 |
| mailhog | Grype | 20 | 97 | 77 | 19 | 3 | 20 |

Overlap by advisory and package (GHSA ids mapped to their CVE alias so one advisory is not counted twice):

| Image | Found by both | Trivy only | Grype only |
|---|---:|---:|---:|
| api.mypremiumdealership.com | 433 | 13 | 8 |
| crapi-community | 259 | 1 | 75 |
| crapi-identity | 651 | 122 | 485 |
| crapi-web | 213 | 1 | 155 |
| crapi-workshop | 434 | 39 | 168 |
| mailhog | 187 | 1 | 29 |

**Reading the comparison.** The tools agree on the bulk of the findings and disagree at the edges, in two
ways that matter when a gate depends on them:

1. **Severity is not the same number.** Grype reports several times more Critical findings than Trivy on the
   same image (crapi-web: 33 vs 2) because the tools prefer different sources for the rating — vendor data
   where Trivy has it, the NVD score where Grype does not. A gate that blocks on "Critical" therefore blocks
   on a different set depending on the tool, which is an argument for pinning one tool per gate and
   recording why.
2. **Coverage differs by ecosystem.** Grype finds hundreds of extras in the Java image (crapi-identity),
   Trivy finds 122 the SBOM scan does not — scanning the image directly sees files an SBOM may omit, and
   vice versa.

None of this blocks a build here: these are a third-party target's images (ADR-003). The numbers are kept so
that the next scan can be compared with this one, and `tools/sca_summary.py` regenerates the tables.

## Reproduce

```bash
make scan-secrets          # Gitleaks over the portfolio repositories
make scan-sast             # Semgrep: own code (gate) and crAPI source (report)
make scan-sca              # Trivy repo + images, Syft SBOMs, Grype, and the summary tables
make gate                  # the blocking gate over the own-code reports
```
