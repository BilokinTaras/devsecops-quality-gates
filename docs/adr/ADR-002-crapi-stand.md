# ADR-002: How the crAPI stand is run

- Status: accepted
- Date: 2026-11-01

## Context

The upstream release compose (`deploy/docker/docker-compose.yml`, tag v1.1.6) references images by the moving
`latest` tag, publishes ports on all interfaces, sets fixed container names, and includes an LLM chatbot that
needs an OpenAI API key. Security scanners and tests must hit exactly the same bytes on every run, never leave
the machine, and coexist with other Compose projects.

## Decision

`stand/compose.yaml`, Compose project `qa-crapi`, derived from the v1.1.6 release compose:

- every image pinned by **digest** (resolved on 2026-11-01); all of them are multi-arch and include
  `linux/arm64` (checked with `docker buildx imagetools inspect`), so Apple Silicon runs them natively;
- `crapi-chatbot` and `chromadb` **removed** — they need an external OpenAI key (out of scope, recorded in the
  threat model); the name `crapi-chatbot` is aliased to the canary so the web gateway's upstream resolves;
- only `crapi-web` (8888) and the MailHog UI (8025) are published, and only on **127.0.0.1**;
- no `container_name`, so all names carry the `qa-crapi` prefix;
- a local **canary** HTTP service (`stand/canary/canary.py`) is the only SSRF destination; it records every
  request it receives so tests can prove the server-side fetch happened;
- CPU and memory limits per service keep the stand within a laptop's budget;
- `stand/keys/jwks.json` is crAPI's public demo key set, required by the identity service.

Test data comes from `security_tests/seed.py` (idempotent): users A and B, each with a vehicle (VIN and PIN
read from the welcome mail in MailHog), a community post and a shop order.

## Alternatives considered

| Option | Pros | Cons | Why not |
|---|---|---|---|
| Upstream compose as is | Zero maintenance | `latest` tags change under the scanners; ports on 0.0.0.0; needs an OpenAI key | Not reproducible, not loopback-only |
| Build crAPI from source | Full control | Long builds, Java/Go/Python toolchains, drift from the released images | The released images are what users run |
| Helm/Kubernetes deploy from upstream | Closer to production | Needs a cluster on the laptop | Too heavy for the goal |

## Consequences

- Updating crAPI = new digests in one file plus a re-run of the whole pipeline; the source tag used for SAST
  (`CRAPI_TAG` in `scripts/lib.sh`) must change together with them.
- The chatbot's LLM vulnerabilities are not covered.
- The stand and the shop (`shop-sut`) are never run together on one laptop.

## Links

- crAPI: https://github.com/OWASP/crAPI (Apache-2.0), release v1.1.6
- Rules of engagement: [../rules-of-engagement.md](../rules-of-engagement.md)
