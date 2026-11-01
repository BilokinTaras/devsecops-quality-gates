# Rules of engagement

These rules apply to every scan, test and script in this repository, locally and in CI.
They are written before any testing starts and are part of the review of every change.

## Scope

| In scope | Out of scope |
|---|---|
| Containers of Compose project `qa-crapi` (OWASP crAPI, pinned by digest) on the machine running the tests | Any host on the internet, including crAPI's public demo instances |
| The `canary` container inside `qa-crapi-net`, as the only SSRF destination | `api.mypremiumdealership.com` beyond what crAPI itself calls; any real third-party API |
| Source code and git history of this portfolio's own repositories (secrets, SAST) | Other people's repositories, organisations or infrastructure |
| Source code of crAPI at the pinned version (SAST, report only) | Reporting crAPI's intentional vulnerabilities upstream as if they were defects |
| Passive scan of the local `shop-sut` stand (optional extension, read-only requests) | Active scans of `shop-sut` |

## Technical guardrails

1. **Loopback only.** crAPI publishes ports on `127.0.0.1` only. Scanners run as containers attached to
   `qa-crapi-net`; host networking is never used.
2. **Targets are allow-listed in configuration.** ZAP contexts include only `http://crapi-web` URLs;
   Nuclei runs against an explicit target list; every pytest request goes through one client whose
   base URL is validated to be a local address.
3. **SSRF goes to the canary only.** Tests never ask crAPI to fetch an external URL. The upstream challenge
   suggests `www.google.com`; this project uses `http://canary:8080/` instead.
4. **Minimal volume.** Brute-force and rate-limit demonstrations send the smallest number of requests that
   proves the behaviour (documented per test, never more than 100 requests in a burst). Nuclei and ZAP run
   with rate limits and a time budget.
5. **No destructive actions outside our own data.** Tests create their own users (A and B) and act on them.
   Seeded users of crAPI are only read.
6. **No real secrets.** Credentials in this repository are crAPI's public demo values or test users created
   by the seed script. The Gitleaks demo uses the fake `QAFAKE_` format only — never a realistic token
   format of a real provider.
7. **One heavy stack at a time.** crAPI and `shop-sut` are not run together on the same laptop.

## Evidence handling

- Reports keep only what is needed to reproduce a finding against localhost.
- JWTs, passwords and personal data in evidence are redacted except crAPI demo values.
- Nothing from this repository's tests is sent to any external service. Upload of SARIF to GitHub code
  scanning (phase 2) contains findings about this repository's own code only.

## Stop conditions

Stop and investigate if any of the following happens:

- a scanner or test reaches an address that is not `127.0.0.1`, a `qa-crapi-net` container or `canary`;
- the laptop becomes unresponsive or a container is OOM-killed during a scan;
- a test would need to modify data of a user it did not create.
