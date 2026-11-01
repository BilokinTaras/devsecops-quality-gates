## Security quality gate: ❌ FAIL

Fails on **new** findings with severity **high** or higher.

| Severity | All findings | New, blocking |
|---|---:|---:|
| critical | 0 | 0 |
| high | 2 | 2 |
| medium | 0 | 0 |
| low | 0 | 0 |
| info | 0 | 0 |

Suppressed by baseline: **0** · expired baseline entries: **0** · stale baseline entries: **0**

### Blocking findings

| Severity | Tool | Rule | Location | Title |
|---|---|---|---|---|
| high | gitleaks | `curl-auth-header` | `stand/ci/deploy-notify.sh:5@0e3ddacdd6b5` | Discovered a potential authorization token provided in a curl command header, which could compromise the curl accessed resource. |
| high | gitleaks | `qafake-demo-token` | `stand/ci/deploy-notify.sh:6@0e3ddacdd6b5` | Fake demo token (QAFAKE_ + 32 upper-case letters or digits) |

Inputs: `gitleaks-json:reports/gitleaks-devsecops-quality-gates.json`, `gitleaks-json:reports/gitleaks-shop-api-pytest.json`, `gitleaks-json:reports/gitleaks-shop-e2e-playwright.json`, `gitleaks-json:reports/gitleaks-shop-performance-k6.json`, `gitleaks-json:reports/gitleaks-shop-sut.json`, `semgrep-json:reports/semgrep.json`, `trivy-json:reports/trivy-repo.json`
