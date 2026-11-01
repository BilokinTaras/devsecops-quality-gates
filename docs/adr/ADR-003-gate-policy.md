# ADR-003: What the security gate blocks

- Status: accepted
- Date: 2026-11-01

## Context

The pipeline scans two very different things: **this repository** (code, configuration, git history), which
the team owns and can fix, and **crAPI**, a third-party application that is vulnerable on purpose. Treating
both the same way either blocks every build forever (crAPI's images carry hundreds of known CVEs) or teaches
people to ignore the gate.

## Decision

`tools/gate` runs with three policies:

| Gate | Inputs | Blocks on | Baseline |
|---|---|---|---|
| `make gate` (code) | Gitleaks (full history of this and sibling portfolio repositories), Semgrep on own code, Trivy on this repository (dependencies, misconfigurations, secrets) | any **new** High or Critical | `security-baseline.yml` — every entry has a reason, an owner and an expiry date |
| `make gate-target` (DAST) | ZAP and Nuclei results against the stand | any **new** High or Critical alert | `stand/target-baseline.yml` — triaged, known crAPI alerts |
| image SCA | Trivy on crAPI images | nothing (`--report-only`) | — reported, counted and compared with Grype |

Expired baseline entries stop suppressing their finding, so accepted risk is revisited, not forgotten.

## Alternatives considered

| Option | Pros | Cons | Why not |
|---|---|---|---|
| One gate over everything | Simple | Permanently red because of the target's own CVEs | Noise destroys trust in the gate |
| Baseline every crAPI CVE | Gate could block image changes | Hundreds of entries with no owner who can act | Fake risk acceptance |
| No gate on DAST | Fewer false alarms | A regression in the stand or scanner config goes unnoticed | DAST output is small enough to triage |

## Consequences

- A new secret, a new High in own code or a new High DAST alert fails the build; the demo branch with a fake
  `QAFAKE_` token proves it.
- Image SCA numbers appear in reports and in `docs/findings-static.md`, not as build failures.
- Baselines need upkeep: entries expire after 90 days by default.

## Links

- Gate implementation and tests: `tools/gate/`, `tests/gate/`
