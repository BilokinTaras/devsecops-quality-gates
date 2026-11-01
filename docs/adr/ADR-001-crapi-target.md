# ADR-001: OWASP crAPI as the target for security testing

- Status: accepted
- Date: 2026-11-01

## Context

The pipeline must demonstrate SAST, SCA, SBOM, DAST and API-security regression tests against a target
that is **legal and safe to attack**, runs locally, has a realistic microservice API with an OpenAPI
specification, and contains known vulnerabilities mapped to the **OWASP API Security Top 10 (2023)** —
so that what scanners catch can be compared with what targeted tests catch.

## Decision

OWASP **crAPI** (completely ridiculous API), release v1.1.6, images pinned by digest, run only on
127.0.0.1 (`stand/compose.yaml`, Compose project `qa-crapi`).

## Alternatives considered

| Option | Pros | Cons | Why not |
|---|---|---|---|
| OWASP Juice Shop | Very popular, many challenges | Mostly web/UI vulnerabilities; monolith; API Top 10 coverage is incidental | The portfolio's focus is API security |
| VAmPI | Small vulnerable REST API, OpenAPI spec | Single service, few vulnerability classes | Too small to show layered testing |
| DVWA | Classic | PHP web app, not an API; dated | Wrong target type |
| The portfolio's own shop (Medusa) | Real product | Not intentionally vulnerable; attacking it proves little and may hide real issues behind noise | Kept for an optional passive-only baseline scan |
| **crAPI** | Built for API Top 10; several services (Java, Go, Python) for SAST variety; OpenAPI spec; MailHog for OTP flows; maintained by OWASP | `latest`-tagged images in the release compose; chatbot needs an OpenAI key | **Chosen**, with digests pinned and the chatbot disabled |

## Consequences

- Images for amd64 and arm64 exist for every service used, so the MacBook demo runs natively without emulation.
- The LLM challenges (chatbot) are out of scope; documented in the threat model.
- Every finding is reproduced against `localhost` only; the rules of engagement apply to every tool.
