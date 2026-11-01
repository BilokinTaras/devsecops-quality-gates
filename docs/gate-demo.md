# Proof that the secrets gate blocks a merge

A gate nobody has seen fail is a gate nobody trusts. The branch `demo/gate-red` carries one file with a
**fake** token so the failure can be reproduced at any time.

## The fake format

`stand/ci/deploy-notify.sh` on `demo/gate-red` contains
`QAFAKE_` followed by 32 upper-case characters. The format is invented for this repository, matched by the
rule `qafake-demo-token` in [`.gitleaks.toml`](../.gitleaks.toml), and deliberately unlike any real provider's
token, so nothing in the history can be mistaken for a live credential.

## Scope of the normal scan

`scripts/scan-secrets.sh` scans every branch **except** `demo/*`
(`git log --all --not --branches=demo/*`), so the demonstration can stay in the repository without keeping
the gate permanently red. In CI the job checks out one branch, so the same command scans exactly the branch
being built — including the demo branch when a pull request opens it.

## Reproduction (2026-11-01)

```bash
sh scripts/scan-secrets.sh && make gate                      # main: 0 leaks, gate PASS, exit 0
GITLEAKS_LOG_OPTS=--all sh scripts/scan-secrets.sh && make gate   # includes demo/*: gate FAIL, exit 1
sh scripts/scan-secrets.sh && make gate                      # back to PASS
```

| Scan | Leaks in this repository | Gate | Exit code |
|---|---:|---|---:|
| Every branch except `demo/*` (26 commits across 5 repositories) | 0 | ✅ PASS | 0 |
| Including `demo/gate-red` | 1 (`qafake-demo-token`, severity high) | ❌ FAIL | 1 |
| Every branch except `demo/*`, again | 0 | ✅ PASS | 0 |

The failing run names the rule, the file and the commit; the value itself is redacted by `--redact`, so the
report can be published.

## Why the finding is not baselined

The baseline accepts a finding only with a reason, an owner and an expiry date. A secret in history is not a
risk to accept — it is removed and the credential rotated. The demonstration branch is therefore never merged;
in phase 2 it becomes a pull request that stays open and closed as evidence, linked from the README.
