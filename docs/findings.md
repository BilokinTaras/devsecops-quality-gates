# Security findings — OWASP crAPI v1.1.6 (local stand)

Fifteen findings reproduced by hand on 2026-11-01 against `http://127.0.0.1:8888`, each with a regression
test in `security_tests/` that asserts the **secure** behaviour and is a strict expected failure while the
stand is vulnerable. Scores are CVSS v3.1 base scores computed by `tools/cvss.py` (checked against published
NVD vectors in `tests/test_cvss.py`), rated for crAPI **as if it were a real product**.

crAPI is intentionally vulnerable; these are its training vulnerabilities, not defects to report upstream.

| ID | Title | OWASP API Top 10 (2023) | CWE | CVSS 3.1 | Test |
|---|---|---|---|---|---|
| [FINDING-001](#finding-001) | All three services accept a JWT with `alg: none` | API2 Broken Authentication | CWE-347 | 9.1 critical | `test_unsigned_token_is_rejected` |
| [FINDING-002](#finding-002) | Identity accepts a token signed with the published demo secret | API2 | CWE-321 | 9.1 critical | `test_token_signed_with_the_published_demo_secret_is_rejected` |
| [FINDING-015](#finding-015) | Identity accepts a genuine token whose payload was edited | API2 | CWE-347 | 9.1 critical | `test_identity_rejects_a_tampered_token` |
| [FINDING-012](#finding-012) | No limit on OTP attempts in `/auth/v2/check-otp` | API2 | CWE-307 | 9.1 critical | `test_otp_check_is_rate_limited` |
| [FINDING-003](#finding-003) | SQL injection in `apply_coupon` | API8 Security Misconfiguration | CWE-89 | 8.8 high | `test_coupon_code_is_not_concatenated_into_sql` |
| [FINDING-005](#finding-005) | SSRF: `contact_mechanic` fetches any URL supplied by the caller | API7 SSRF | CWE-918 | 7.7 high | `test_contact_mechanic_does_not_fetch_a_caller_supplied_url` |
| [FINDING-006](#finding-006) | Any user can read any vehicle's live location | API1 BOLA | CWE-639 | 6.5 medium | `test_vehicle_location_of_another_user_is_refused` |
| [FINDING-007](#finding-007) | Any user can read any order by id | API1 BOLA | CWE-639 | 6.5 medium | `test_order_of_another_user_is_refused` |
| [FINDING-008](#finding-008) | Any user can read any mechanic report by id | API1 BOLA | CWE-639 | 6.5 medium | `test_mechanic_report_of_another_user_is_refused` |
| [FINDING-009](#finding-009) | A customer can delete any user's video through the admin route | API5 BFLA | CWE-285 | 6.5 medium | `test_admin_video_route_is_refused_to_a_customer` |
| [FINDING-010](#finding-010) | The management user list is open to any authenticated user | API5 BFLA | CWE-285 | 6.5 medium | `test_management_user_list_is_refused_to_a_customer` |
| [FINDING-004](#finding-004) | NoSQL injection in coupon validation | API8 | CWE-943 | 5.4 medium | `test_coupon_validation_rejects_mongo_operators` |
| [FINDING-013](#finding-013) | Service reports can be created without authentication | API5 | CWE-306 | 5.3 medium | `test_service_report_creation_requires_authentication` |
| [FINDING-011](#finding-011) | Community feed exposes other users' e-mail and vehicle id | API3 Broken Object Property Level Authorization | CWE-213 | 4.3 medium | `test_community_posts_do_not_expose_personal_data` |
| [FINDING-014](#finding-014) | A customer can set the fulfilment status of their order | API3 (mass assignment) | CWE-915 | 4.3 medium | `test_order_status_is_not_client_writable` |

Chains worth noting: **FINDING-011 → FINDING-012** (the feed hands out the e-mail addresses that the
unthrottled OTP endpoint needs) and **FINDING-006/008 → FINDING-003** (identifiers and phone numbers read
from one endpoint feed the next).

What crAPI gets **right** is tested too, as positive controls: anonymous requests are refused, the community
and workshop services verify the token's algorithm and signature, another user's order cannot be modified,
and `/auth/v3/check-otp` throttles after ten attempts. Those ten tests must pass, so a change that breaks
them is caught as a regression.

---

## FINDING-001

**All three services accept a JWT with `alg: none`** · API2:2023 · CWE-347 · CVSS 3.1
`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` = **9.1 critical**

**Endpoint / precondition.** `identity`, `community` and `workshop`; the attacker needs only a victim's
e-mail address, which the community feed publishes (FINDING-011).

**Reproduction** (localhost only):

```python
header  = base64url({"alg": "none", "typ": "JWT"})
payload = base64url({"sub": "qa-bob@example.com", "role": "user", "iat": ..., "exp": ...})
token   = f"{header}.{payload}."          # empty signature
GET /identity/api/v2/user/dashboard        Authorization: Bearer <token>   -> 200
GET /community/api/v2/community/posts/recent                               -> 200
GET /workshop/api/shop/orders/all                                          -> 200
```

**Evidence.** The identity dashboard returns Bob's name, e-mail, phone number and credit balance; the
workshop returns Bob's orders. Genuine tokens are RS256 (`{"alg":"RS256"}` in the login response).

**Impact.** Complete authentication bypass as any user, without a password, a stolen token or any
interaction. Everything the other findings require a session for becomes reachable.

**Fix.** Pin the accepted algorithm to RS256 and reject tokens whose header says otherwise; never call a
decoder with signature verification disabled. The crAPI source shows the pattern Semgrep also flagged
(`unverified-jwt-decode` in `services/workshop`, `jwt-go-parse-unverified` in `services/community`).

**Regression test.** `security_tests/test_authentication.py::test_unsigned_token_is_rejected` (per service).

## FINDING-002

**Identity accepts a token signed with the published demo secret** · API2:2023 · CWE-321 · CVSS 3.1
`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` = **9.1 critical**

**Reproduction.** Sign the same claims with HS256 and the key `crapi` — the value shipped as `JWT_SECRET`
in crAPI's own compose file — and call `GET /identity/api/v2/user/dashboard`: **200** with the victim's
profile. The same token is refused by community and workshop (**401**), which is the positive control.

**Impact.** Account takeover of any user by anyone who has read the project's public configuration.

**Fix.** One key source, asymmetric verification only, no hard-coded or shipped secrets; rotate on deploy.

**Regression test.** `test_token_signed_with_the_published_demo_secret_is_rejected`, plus
`test_community_and_workshop_reject_the_demo_secret` as the control.

## FINDING-015

**Identity accepts a genuine token whose payload was edited** · API2:2023 · CWE-347 · CVSS 3.1
`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` = **9.1 critical**

Same root cause as FINDING-002 — the identity service does not verify signatures at all — recorded
separately because it is a different attack and a different test. Taking a valid session token, changing
`role` to `admin` and keeping the original signature still returns **200**. Community and workshop refuse
the same token.

**Found by accident:** this test was written as a positive control, assuming every service would refuse a
broken signature. It failed, which is how the finding was discovered.

**Regression test.** `test_identity_rejects_a_tampered_token`; the control is
`test_community_and_workshop_reject_a_tampered_token`.

## FINDING-012

**No limit on OTP attempts in `/auth/v2/check-otp`** · API2:2023 · CWE-307 · CVSS 3.1
`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` = **9.1 critical**

**Reproduction** (20 attempts against an account this suite created, per the rules of engagement):
`POST /identity/api/auth/forget-password` then 20 × `POST /identity/api/auth/v2/check-otp` with wrong
codes — all 20 answered **500**, none throttled. The same 20 attempts against `/auth/v3/check-otp` are
blocked with **503** after the tenth.

**Impact.** The OTP is four digits, so the whole key space is 10 000 attempts; at the measured rate of
~33 requests/s that is roughly five minutes to take over an account whose e-mail is known — and the
community feed publishes e-mail addresses (FINDING-011).

**Fix.** Retire v2; apply v3's throttling (and an attempt counter bound to the reset request) everywhere.

**Regression test.** `test_otp_check_is_rate_limited`; control `test_otp_v3_is_rate_limited`.

## FINDING-003

**SQL injection in `apply_coupon`** · API8:2023 · CWE-89 · CVSS 3.1
`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = **8.8 high**

**Reproduction.** As any logged-in customer:

```http
POST /workshop/api/shop/apply_coupon
{"coupon_code": "'; SELECT number FROM user_login WHERE email='qa-bob@example.com", "amount": 75}

400 {"message":"9000000002 Coupon code is already claimed by you!! ..."}
```

`9000000002` is **another user's** phone number, read out of the `user_login` table and returned in the
error message. A single quote alone (`"coupon_code": "'"`) returns a Django 500 error page, which is how
the injection point was spotted.

**Evidence from the source** (`services/workshop/crapi/shop/views.py`, `ApplyCouponView`): the value is
concatenated into `cursor.execute(...)`. Semgrep's `p/security-audit` pack did **not** flag this line; the
finding came from the manual probe, which is the point of running both.

**Impact.** Arbitrary read of the application database (user table included) and, because the statement
separator is accepted, arbitrary statements — hence integrity and availability are rated High as well.

**Fix.** Parameterised queries or the ORM; never interpolate request data into SQL; turn off detailed error
pages in production.

**Regression test.** `test_coupon_code_is_not_concatenated_into_sql` (asserts that another user's phone
number never appears in the response).

## FINDING-005

**SSRF: `contact_mechanic` fetches any URL supplied by the caller** · API7:2023 · CWE-918 · CVSS 3.1
`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N` = **7.7 high**

**Reproduction.** `POST /workshop/api/merchant/contact_mechanic` with
`"mechanic_api": "http://canary:8080/ssrf-proof"`. The response embeds the canary's body
(`{"canary":"QA-SSRF-CANARY-7f3c", ...}`) and the canary records the inbound request from the workshop
container (`172.22.0.9`). **Only the stand's canary is ever used as a destination** (rules of engagement,
guardrail 3).

**Impact.** The server fetches attacker-chosen URLs and returns the body, so anything the workshop container
can reach — other services on the internal network, cloud metadata endpoints in a real deployment — is
readable from outside. Scope is Changed because the request crosses into the internal network.

**Fix.** Do not take an endpoint URL from the request; resolve the mechanic's address server-side from the
mechanic code, and allow-list the hosts the service may call.

**Regression test.** `test_contact_mechanic_does_not_fetch_a_caller_supplied_url` (asserts the canary was
never contacted).

## FINDING-006

**Any user can read any vehicle's live location** · API1:2023 · CWE-639 · CVSS 3.1
`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` = **6.5 medium**

`GET /identity/api/v2/vehicle/{uuid}/location` with Alice's token and Bob's vehicle id returns **200** with
latitude, longitude, owner's full name and e-mail. Anonymous requests are correctly refused (**401**), so
the check that exists is "is there a token", not "is this your car".

**Impact.** Physical tracking of any owner whose vehicle id is known; vehicle ids are published by the
community feed (FINDING-011), so the identifier is not a secret.

**Fix.** Authorise on the object: the vehicle must belong to the caller.

**Regression test.** `test_vehicle_location_of_another_user_is_refused`; controls
`test_own_vehicle_location_is_allowed` and `test_vehicle_location_requires_authentication`.

## FINDING-007

**Any user can read any order by id** · API1:2023 · CWE-639 · CVSS 3.1
`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` = **6.5 medium**

`GET /workshop/api/shop/orders/{id}` returns another customer's order: product, quantity, status, the
buyer's e-mail and phone number, and the payment transaction id. Order ids are small integers, so the whole
order history of the shop can be enumerated.

**Notable asymmetry:** `PUT` on the same order **is** authorised (**403**), which shows the ownership check
exists and was simply not applied to the read path. That asymmetry is the positive control
`test_changing_another_users_order_is_refused`.

**Fix.** Apply the same ownership check to reads; use unguessable identifiers.

**Regression test.** `test_order_of_another_user_is_refused`.

## FINDING-008

**Any user can read any mechanic report by id** · API1:2023 · CWE-639 · CVSS 3.1
`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` = **6.5 medium**

`GET /workshop/api/mechanic/mechanic_report?report_id=1` returns a report belonging to another customer:
owner's e-mail and phone number, the vehicle's VIN and the free-text problem description (which in the
seeded data contains the owner's own phone number and e-mail). Report ids are sequential.

**Fix.** Authorise by owner or assigned mechanic.

**Regression test.** `test_mechanic_report_of_another_user_is_refused`.

## FINDING-009

**A customer can delete any user's video through the admin route** · API5:2023 · CWE-285 · CVSS 3.1
`AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` = **6.5 medium**

`DELETE /identity/api/v2/admin/videos/{id}` with Bob's ordinary customer token deletes Alice's video:
**200 "User video deleted successfully."** The route checks that a token exists, not that it carries an
administrative role.

**Impact.** Destruction of other users' data by any registered customer. Rated I:H because the deletion is
permanent for the affected object; no confidentiality impact.

**Fix.** Enforce the role on every `/admin/` route, server-side, in one place.

**Regression test.** `test_admin_video_route_is_refused_to_a_customer` (creates and cleans up its own video).

## FINDING-010

**The management user list is open to any authenticated user** · API5:2023 · CWE-285 · CVSS 3.1
`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` = **6.5 medium**

`GET /workshop/api/management/users/all` returns every user of the shop with e-mail, phone number and
credit balance, to any logged-in customer.

**Impact.** Bulk harvesting of the user base: the input for the OTP brute force (FINDING-012) and for
enumerating objects in the BOLA findings.

**Fix.** Role check plus pagination limits on administrative listings.

**Regression test.** `test_management_user_list_is_refused_to_a_customer`.

## FINDING-004

**NoSQL injection in coupon validation** · API8:2023 · CWE-943 · CVSS 3.1
`AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N` = **5.4 medium**

`POST /community/api/v2/coupon/validate-coupon` with `{"coupon_code": {"$ne": "zzz"}}` (or `{"$gt": ""}`)
returns a real coupon — `{"coupon_code":"TRAC075","amount":"75"}` — while an unknown string returns an
error. A JSON object is passed into the MongoDB query where a string is expected.

**Impact.** Any customer can obtain valid discount coupons without knowing a code, and can confirm which
coupons exist.

**Fix.** Validate the type of every field before it reaches the query; reject objects where a string is
expected.

**Regression test.** `test_coupon_validation_rejects_mongo_operators` (both operators); control
`test_unknown_coupon_is_rejected`.

## FINDING-013

**Service reports can be created without authentication** · API5:2023 · CWE-306 · CVSS 3.1
`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` = **5.3 medium**

`GET /workshop/api/mechanic/receive_report` with no token creates a service request for an arbitrary VIN and
returns a link to the new report. The OpenAPI specification also declares this operation without a security
requirement, so the specification and the implementation agree — on being open.

**Impact.** Anyone who can reach the API can fill the mechanics' queue and create reports against other
people's vehicles.

**Fix.** Require authentication, or restrict the route to the internal network if it is a service-to-service
callback — and say so in the specification.

**Regression test.** `test_service_report_creation_requires_authentication`.

## FINDING-011

**Community feed exposes other users' e-mail and vehicle id** · API3:2023 · CWE-213 · CVSS 3.1
`AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` = **4.3 medium**

`GET /community/api/v2/community/posts/recent` returns, for every post,
`author.email` and `author.vehicleid` next to the nickname. The web client shows only the nickname, so the
data is invisible in the browser and present in the response.

**Impact.** The directory an attacker needs for the rest of the chain: e-mail addresses for the OTP brute
force (FINDING-012) and vehicle ids for the location BOLA (FINDING-006).

**Fix.** Serialise only what the client renders; build responses from an explicit field list rather than
dumping the model.

**Regression test.** `test_community_posts_do_not_expose_personal_data`.

## FINDING-014

**A customer can set the fulfilment status of their order** · API3:2023 · CWE-915 · CVSS 3.1
`AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N` = **4.3 medium**

`PUT /workshop/api/shop/orders/{own id}` with `{"status": "returned"}` changes the stored status, which the
shop treats as a return (the credit flow follows from it). The field is accepted straight from the request
body.

**Scope note.** Only the caller's own order: the same request against another user's order is correctly
refused with **403** (positive control). The finding is mass assignment, not a broken ownership check.

**Fix.** Bind only the fields a customer may change; move status transitions behind the return workflow.

**Regression test.** `test_order_status_is_not_client_writable` (creates its own order, so it does not
depend on what other tests left behind).

---

## Observations (not rated)

| ID | Observation | Why it is recorded |
|---|---|---|
| OBS-1 | The identity service answers **404** instead of 401 to an unauthenticated request for `/user/dashboard` | The request is refused, so it is not a vulnerability, but the status misleads clients and monitoring. The regression tests accept 401, 403 or 404 as "refused" and say why. |
| OBS-2 | The LLM chatbot challenges are not covered | `crapi-chatbot` needs an external OpenAI key and is removed from the stand ([ADR-002](adr/ADR-002-crapi-stand.md)) |
| OBS-3 | Shell injection through video conversion parameters was not attempted | The stand sets `ENABLE_SHELL_INJECTION=false`; with it enabled the host-side risk is out of proportion to the demonstration |
