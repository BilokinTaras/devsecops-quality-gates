# What the scanners caught, and what they did not (2026-11-01)

Three automated layers ran against the same stand as the manual testing: Semgrep over crAPI's source, ZAP's
Automation Framework against the running API, and Nuclei. This page compares their output with the fifteen
findings in [findings.md](findings.md), which were reproduced by hand.

## The short version

| Layer | Tool | Findings reported | Of the 15 manual findings, how many | Max severity |
|---|---|---:|---:|---|
| SAST | Semgrep 1.183.0, 374 source files | 54 | **2 partially** (`unverified-jwt-decode`, `jwt-go-parse-unverified` point at FINDING-001) | ERROR |
| DAST | ZAP 2.17.0, API policy, 140 URLs | 9 alert types | **0** | Medium |
| DAST | Nuclei 3.11.1, 3 546 templates | 24 (all one template, informational) | **0** | Info |
| Manual + regression tests | — | 15 | 15 | Critical |

The scanners did not find a single one of the authorization findings, the SQL injection, the SSRF or the
missing rate limit. They did find nine classes of issue that the manual tests never looked for.

## ZAP

Configuration: `stand/zap-plan.yaml` — context restricted to `http://crapi-web`, the pinned OpenAPI
specification imported (44 URLs), spider limited to depth 5 (96 URLs), active scan with the `API` policy and
a 12-minute budget, authenticated by injecting a bearer token through a replacer rule. Reports: HTML, JSON
and SARIF in `reports/zap/`.

| Alert | Risk | Instances |
|---|---|---:|
| Content Security Policy (CSP) Header Not Set | Medium | 5 |
| Cross-Domain Misconfiguration | Medium | 5 |
| Missing Anti-clickjacking Header | Medium | 1 |
| Server leaks version information via the `Server` header | Low | 5 |
| Application Error Disclosure | Low | 5 |
| X-Content-Type-Options Header Missing | Low | 5 |
| Timestamp Disclosure | Low | 2 |
| Modern Web Application / Authentication Request Identified | Info | 5 |

Worth noticing: **Application Error Disclosure (Low)** is the same Django 500 page that gave away the SQL
injection of FINDING-003 during manual testing. ZAP saw the symptom and rated it Low; nobody reading a
"Low: error page" line would have found the injection behind it.

## Nuclei

Templates tagged `misconfig`, `exposure`, `tech` and `default-login` against three entry points, rate
limited to 20 requests/s: **0 matches** in 621 requests. The second pass
(`-id http-missing-security-headers`) reports 24 matches across the three entry points — ten header types,
all informational — and exists as a self-check: an empty result from the first pass now means "nothing
matched", not "the scanner never reached the target".

That distinction was learned the hard way. The first Nuclei run reported 0 findings and had in fact scanned
nothing: nuclei resolves hostnames with its own resolvers and could not see Docker's internal DNS
(`Skipped crapi-web:80 ... no address found for host`). The fix is `-system-resolvers`. **A scanner that
reports nothing is indistinguishable from a scanner that ran nothing, unless you make it prove otherwise.**

## Semgrep

54 findings over crAPI's source, triaged in [findings-static.md](findings-static.md). Two of them point at
the root cause of FINDING-001 (`unverified-jwt-decode` in the workshop, `jwt-go-parse-unverified` in the
community service) — the only overlap between the automated layers and the manual findings.

Semgrep **missed the SQL injection**: zero rules matching `sql` fired across 374 files, although
`services/workshop/crapi/shop/views.py` concatenates a request value into `cursor.execute`. In that same
file it reported only `verify=False` on an outbound request.

## Why the gap exists

| Finding class | Why a scanner misses it |
|---|---|
| BOLA / BFLA (FINDING-006…010) | The scanner has one identity and no notion of "whose object is this". A 200 for `/vehicle/{other id}/location` looks like a successful request, not a violation. Detecting it needs two accounts and an expectation about ownership — which is what the regression tests encode. |
| Mass assignment (FINDING-014) | Requires knowing which fields a client may legitimately set; the API accepts the request and answers 200. |
| Excessive data exposure (FINDING-011) | Requires knowing that `email` is not meant to be in a public feed. The response is valid JSON with a 200. |
| Missing rate limit (FINDING-012) | A scanner avoids sending hundreds of identical requests by design; and the absence of a response is the signal. |
| SSRF (FINDING-005) | Needs an out-of-band listener the scanner controls and can verify. ZAP can do this with OAST, which was deliberately not enabled: it would send traffic to an external service, outside the rules of engagement. The project uses a local canary instead. |
| SQL injection (FINDING-003) | Here it is a scanner-tuning failure rather than a conceptual one. The endpoint needs a valid session, a JSON body and a coupon code the API accepts, and the evidence is a value echoed into a 400 message — not a timing difference or a stack trace. |

## What this means for the pipeline

1. **Scanners are a floor, not a ceiling.** They cover the classes nobody should have to re-test by hand
   (headers, known CVEs, outdated components) and they run on every change. Everything that depends on
   business meaning — ownership, roles, which field belongs to whom — needs tests written by someone who
   knows the domain.
2. **Both layers are gated differently** ([ADR-003](adr/ADR-003-gate-policy.md)): new High or Critical from
   the scanners blocks, and the fifteen regression tests must keep their exact strict-xfail status, so a
   change in either direction is caught.
3. **Every scanner needs a self-check.** Nuclei got an explicit one; ZAP's equivalent is that its report
   must contain the URLs from the OpenAPI import, and Semgrep's is the rule count in its SARIF output.

## Reproduce

```bash
make stand-up && make seed
make scan-dast      # ZAP (~4 min incl. 2 min active scan) and Nuclei (~1 min)
make gate-target    # the DAST gate against stand/target-baseline.yml
```
