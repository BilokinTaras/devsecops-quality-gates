# Proof that the secrets gate blocks a merge

A gate nobody has seen fail is a gate nobody trusts. The branch `demo/gate-red` carries one file with a
**fake** token so the failure can be reproduced at any time.

## The fake format

`stand/ci/deploy-notify.sh` on `demo/gate-red` contains `QAFAKE_` followed by 32 upper-case characters. The
format is invented for this repository, matched by the rule `qafake-demo-token` in
[`.gitleaks.toml`](../.gitleaks.toml), and deliberately unlike any real provider's token, so nothing in the
history can be mistaken for a live credential.

## Scope of the normal scan

`scripts/scan-secrets.sh` scans every branch **except** `demo/*`
(`git log --exclude=refs/heads/demo/* --all`), so the demonstration can stay in the repository without
keeping the gate permanently red. In CI the job checks out one branch, so the same command scans exactly the
branch being built — including the demo branch when a pull request opens it.

The exclusion needs `--exclude=<glob>` before `--all`. The obvious-looking
`--all --not --branches=demo/*` removes every commit **reachable from** the demo branch, which is the entire
history: the first version of this script reported 0 commits scanned and a green gate. Found while writing
this page, which is the point of demonstrating a gate instead of describing it.

## Reproduction (2026-11-01)

```bash
sh scripts/scan-secrets.sh && make gate                            # main
GITLEAKS_LOG_OPTS=--all sh scripts/scan-secrets.sh && make gate    # includes demo/*
sh scripts/scan-secrets.sh && make gate                            # back to main
```

| Scan | Leaks in this repository | Gate | Exit code |
|---|---:|---|---:|
| Every branch except `demo/*` (4 commits here, 26 across the 5 portfolio repositories) | 0 | ✅ PASS | 0 |
| Including `demo/gate-red` (5 commits) | 2 | ❌ FAIL | 1 (`make` reports 2) |
| Every branch except `demo/*`, again | 0 | ✅ PASS | 0 |

Both findings sit on the same two lines of the demo file and are both High:

| Rule | Source | What it caught |
|---|---|---|
| `qafake-demo-token` | this repository's `.gitleaks.toml` | the invented `QAFAKE_…` format |
| `curl-auth-header` | Gitleaks' default rule set | the `Authorization: Bearer …` header in the `curl` call |

The second one was not planned: the built-in rules catch the pattern as well, which is a useful reminder that
a custom rule is an addition to the default set, not a replacement for it.

The failing report names the rule, the file, the line and the commit; the value itself is redacted by
`--redact`, so the report can be published and uploaded to code scanning.

## Why the finding is not baselined

The baseline accepts a finding only with a reason, an owner and an expiry date. A secret in history is not a
risk to accept — it is removed and the credential rotated. The demonstration branch is therefore never merged;
in phase 2 it becomes a pull request that stays open and closed as evidence, linked from the README.
