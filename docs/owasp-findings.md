# OWASP findings — target-shop v1 → v2

All findings below were discovered and verified by actually running the listed tool against the live
`target-shop` container on the isolated `lab` Docker network (never against a real host — see
`lab/guard.sh`), not inferred from reading the source. Each finding's **Sentinel detection** column names
the rule that fired live, through the real Kafka → normalizer → rule-engine → Postgres pipeline, on that
exact attack traffic (verified in T9; re-confirmed here for v1, re-tested against v2 in this task).

Every finding is closed in v2 (`SHOP_VERSION=v2`), the same codebase with the vulnerable branch replaced,
selected by `ShopProperties.secure()`. v2 was rebuilt, redeployed and the **same attack re-run** against
it for this report — the "after" column is a real result, not an assumption from reading the diff.

## Summary

| | v1 | v2 |
|---|---|---|
| Findings open (F-01 .. F-14) | **14** | **0** |
| sqlmap: parameter injectable | yes (3 techniques: boolean-blind, error-based, UNION) | **no** — "all tested parameters do not appear to be injectable" |
| Hydra: credentials recovered (200 attempts, real wordlist) | **4 / 4** seed accounts (`admin`, `alice`, `bob`, `carol`) | **0 / 4** |
| ZAP full active scan, WARN-NEW | **8** | **0** (113 PASS) |
| JUnit: exploit-must-succeed tests (`V1VulnerabilitiesTest`) | 17/17 pass (confirms every exploit works) | n/a |
| JUnit: exploit-must-fail tests (`V2FixesTest`) | n/a | 19/19 pass (confirms every exploit now fails) |

Raw tool output backing every row above is in `results/lab/` (file names referenced per finding below) and
is the literal, unedited output of the run; nothing here is summarized from source-code review alone.

---

## F-01 — SQL injection in login (OWASP A03:2021 Injection)
**Severity: Critical.** Username/password are concatenated directly into the SQL string in `AuthController`.

- **Evidence:** `admin'--` as the username with any password returns `role: admin` and a valid session
  token — authentication is bypassed outright. Confirmed manually and via `V1VulnerabilitiesTest.f01_sqlInjectionBypassesLogin`.
- **Sentinel detection:** `SEN-002` (SQL injection attempt, T1190) — fired live on this exact payload during T9.
- **v2 fix:** parameterised `PreparedStatement` via `JdbcTemplate.queryForObject(..., username)`. Re-tested:
  the same payload, and `' OR '1'='1' --`, both return `401 invalid credentials`
  (`V2FixesTest.f01_sqlInjectionNoLongerBypassesLogin`).

## F-02 — No rate limit or account lockout on login (OWASP A07:2021 Identification and Authentication Failures)
**Severity: High.** Unlimited login attempts, no backoff, no lockout.

- **Evidence:** `lab/03_hydra.sh` ran 200 real HTTP requests (8 users × 25 passwords) against v1 with **no
  slowdown or refusal**, recovering all 4 seed credentials: `admin/admin`, `alice/sunshine`, `bob/letmein`,
  `carol/qwerty123` (`results/lab/hydra_20261002T002551.txt`).
- **Sentinel detection:** `SEN-001` (brute-force login, T1110) — fired live (`event_count=7` for the `admin`
  account) during the same Hydra run, confirmed in T9.
- **v2 fix:** `LoginGuard` — max 10 attempts/minute per source IP (429 past it) and account lockout for 15
  minutes after 5 consecutive failures (423), independent of IP. Re-tested: the identical Hydra run against
  v2 recovered **0 of 4** credentials (`results/lab/hydra_20261002T004543.txt`); isolated manual test
  confirmed 5 wrong attempts for `carol` return 401 and the 6th returns 423, while an unrelated account
  (`bob`) logs in normally in parallel — the lockout is per-account, not a site-wide outage.

## F-03 — Unsalted MD5 password storage (OWASP A02:2021 Cryptographic Failures)
**Severity: High.** `DataInitializer.md5()` — fast, unsalted, broken hash.

- **Evidence:** `GET /admin/users` (itself F-10) returns `password: "21232f297a57a5a743894a0e4a801fc3"` for
  `admin`, the well-known MD5 of the string `admin` (`V1VulnerabilitiesTest.f03_passwordsAreUnsaltedMd5`).
- **Sentinel detection:** not directly detectable from network traffic (this is a data-at-rest weakness);
  it is what makes F-10's data exposure far worse, since the exposed hashes are trivially crackable.
- **v2 fix:** BCrypt (`BCryptPasswordEncoder`, cost 10, random salt per password). Re-tested: every stored
  hash starts with `$2a$`, and no account's hash is 32 hex characters (`V2FixesTest.f03_passwordsAreBcrypt`).

## F-04 — User enumeration and verbose login errors (OWASP A07:2021 / A05:2021)
**Severity: Medium.** Login failure messages differ for "unknown user" vs "wrong password", and a
malformed username (`'`) returns the raw SQL statement in a 500 response.

- **Evidence:** `results/lab/sqlmap_20261002T000503/172.30.0.11/log` shows sqlmap's heuristic engine
  immediately fingerprinting the backend as H2 from these verbose errors; manually confirmed the two
  distinct error strings (`V1VulnerabilitiesTest.f04_userEnumerationAndVerboseErrors`).
- **Sentinel detection:** the verbose-error class of response is what feeds F-01's SEN-002 detection its
  highest-confidence signal (the leaked SQL text itself matches the SEN-002 pattern).
- **v2 fix:** one identical `{"error":"invalid credentials"}` for every failure reason, no SQL or stack
  trace ever returned. Re-tested: unknown-user and wrong-password responses are byte-identical
  (`V2FixesTest.f04_errorsAreGeneric`).

## F-05 — Forgeable session tokens (OWASP A07:2021 Identification and Authentication Failures)
**Severity: Critical.** v1's "token" is `base64("username:role")` — no signature, no server-side state.

- **Evidence:** `base64("alice:admin")` submitted as a bearer token is accepted and grants admin access to
  `alice`'s orders without ever knowing her password (`V1VulnerabilitiesTest.f05_tokensAreForgeable`).
- **Sentinel detection:** not a network-visible signal by itself; it is the mechanism that turns any other
  finding (e.g. F-07/F-08 XSS stealing a displayed username) into full account takeover.
- **v2 fix:** `Sessions` issues a random 256-bit hex token held server-side with a 30-minute expiry; the role
  is read from the database on every request, never trusted from the token. Re-tested: the same forged
  `base64("alice:admin")` string now returns 401, and a genuine token is a 64-character hex string
  (`V2FixesTest.f05_tokensAreRandomAndForgeriesFail`).

## F-06 — SQL injection in product search (OWASP A03:2021 Injection)
**Severity: Critical.** `/api/search?q=` and `/search?q=` concatenate the query into SQL.

- **Evidence:** sqlmap confirmed three independent injection techniques — boolean-based blind, H2
  error-based, and UNION-based (4 columns) — in `results/lab/sqlmap_20261002T000503/`, and manually dumped
  every username and password hash from the `users` table via
  `zzz' UNION SELECT id, username, 0, password FROM users --`.
- **Sentinel detection:** `SEN-002` fired live and repeatedly (39 and 36 matching events across the T9 and
  T10 sqlmap/ZAP runs respectively) — see `incidents` table, rule `SEN-002`.
- **v2 fix:** parameterised `LIKE ?` query. Re-tested: the identical sqlmap invocation against v2 reports
  "all tested parameters do not appear to be injectable" (`results/lab/sqlmap_20261002T004530/`), and the
  same manual UNION payload returns `[]` (`V2FixesTest.f06_searchInjectionReturnsNothing`).

## F-07 — Reflected XSS in search results page (OWASP A03:2021 Injection)
**Severity: High.** The raw query string is written into the HTML response unescaped.

- **Evidence:** `<script>alert(1)</script>` as `q` is reflected verbatim into the page
  (`V1VulnerabilitiesTest.f07_reflectedXss`); ZAP's active scan independently rediscovered this with its own
  payload (`</p><scrIpt>alert(1);</scRipt><p>`), reported as `Cross Site Scripting (Reflected) [40012]`.
- **Sentinel detection:** `SEN-003` fired live on both our own test payload and ZAP's independently-generated
  one during T9/T10.
- **v2 fix:** `HtmlUtils.htmlEscape` on every reflected value. Re-tested: the script tag now appears HTML-entity-encoded in the response (`&lt;script&gt;...`), and the ZAP re-scan against v2 reports 0 XSS findings
  (`results/lab/zap_full_20261002T005243.html`).

## F-08 — Stored XSS in product comments (OWASP A03:2021 Injection)
**Severity: High.** Comment `author`/`body` are stored and rendered unescaped on every later view.

- **Evidence:** posting `<img src=x onerror=alert(1)>` as a comment and then loading the product page
  returns it unescaped, persistently, for every visitor (`V1VulnerabilitiesTest.f08_storedXss`); ZAP's
  crawler also flagged a DOM-based variant (`Cross Site Scripting (DOM Based) [40026]`) reachable through
  the same unescaped rendering path.
- **Sentinel detection:** `SEN-003` (same rule as F-07; the stored payload re-triggers it on the write request).
- **v2 fix:** `Html.esc()` on both `author` and `body` at render time, plus length limits (comment body
  capped at 500 characters, rejected above that with 400). Re-tested: the same payload is now rendered as
  `&lt;img src=x onerror=alert(1)&gt;` (`V2FixesTest.f08_storedCommentsAreEncodedOnOutput`).

## F-09 — Insecure direct object reference on orders (OWASP A01:2021 Broken Access Control)
**Severity: Critical.** `/api/orders/{id}` returns any order, including the delivery address, to anyone,
logged in or not, by simply incrementing `id`.

- **Evidence:** `GET /api/orders/6` with no `Authorization` header at all returns the admin's order,
  including the real delivery address (`V1VulnerabilitiesTest.f09_idorExposesAnyOrderWithoutLogin`).
- **Sentinel detection:** not a single-request signal on its own; a script iterating `id` sequentially would
  trip `SEN-004`-class reconnaissance if done over the network layer, but an application-layer IDOR walk is
  presently only visible as an unusually high count of `/api/orders/{id}` 200 responses from one source —
  a gap recorded in `docs/known-limitations.md` as a candidate future rule.
- **v2 fix:** requires a valid session and checks `order.user_id == caller.id` (or admin), returning 404 —
  not 403 — for both a missing order and someone else's order, so the two cases are indistinguishable from
  outside. Re-tested live: `alice` reading her own order 1 → 200; `alice` reading `bob`'s order 3 → 404;
  no token at all → 401; `admin` can still read any order (`V2FixesTest.f09_ordersAreProtectedByOwnership`,
  and manually re-confirmed against the real running v2 container in this task).

## F-10 — Admin endpoint with no authentication (OWASP A01:2021 Broken Access Control)
**Severity: Critical.** `/admin/users` returns every user, including role and password hash, to anyone.

- **Evidence:** `GET /admin/users` with no credentials returns the full user table including password
  hashes (`V1VulnerabilitiesTest.f10_adminEndpointNeedsNoAuthentication`).
- **Sentinel detection:** `SEN-005` would fire if accessed with a scanner tool's user-agent (as it did when
  ZAP/sqlmap/Hydra probed the app generally); the endpoint itself carries no distinguishing signal from a
  normal browser request, which is itself part of the finding.
- **v2 fix:** requires a valid session with the `admin` role; returns 401 with no token, 403 for a
  non-admin token, and the response never includes password hashes even for an admin. Re-tested live against
  the real v2 container: no token → 401; `bob`'s (customer) token → 403; `admin`'s token → 200 without
  password fields (`V2FixesTest.f10_adminEndpointRequiresTheAdminRole`). Also fixed: v1's hardcoded
  `admin/admin` no longer works in v2 — the admin password is configured or randomly generated at startup
  (`V2FixesTest.f10_defaultAdminPasswordNoLongerWorks`).

## F-11 — Debug endpoint leaking configuration and credentials (OWASP A05:2021 Security Misconfiguration)
**Severity: High.** `/debug/config` (no authentication) returns the datasource URL, datasource password,
Java version, and the literal string `admin/admin` as the "default login".

- **Evidence:** `GET /debug/config` returns `datasourcePassword` and `adminDefaultLogin` in plaintext JSON
  (`V1VulnerabilitiesTest.f11_debugEndpointLeaksConfiguration`).
- **Sentinel detection:** none specific; this is exactly the kind of forgotten debug surface the OWASP
  findings process exists to catch independently of runtime detection.
- **v2 fix:** the endpoint is removed entirely (404). Re-tested live against the real v2 container: `GET
  /debug/config` → 404 (`V2FixesTest.f11_debugEndpointIsGone`, re-confirmed manually in this task).

## F-12 — Path traversal in file download (OWASP A01:2021 Broken Access Control)
**Severity: High.** `/api/files?name=` joins the parameter onto the files directory with no checks.

- **Evidence:** `GET /api/files?name=../secret.txt` returns the contents of a file one directory above the
  intended served directory (`V1VulnerabilitiesTest.f12_pathTraversalReadsFilesOutsideTheDirectory`).
- **Sentinel detection:** `SEN-009` (path traversal, T1190) — fired live during T9 on this exact payload
  class (also against variants like `....//....//etc/shadow` from the broader scenario traffic).
- **v2 fix:** the requested path is resolved and normalised, then must (a) stay inside the files directory
  and (b) end in `.txt`. Re-tested live against the real v2 container: `../secret.txt`, `..\secret.txt`,
  `/etc/passwd` and a nested-traversal variant all return 404; a legitimate file (`catalog.txt`) still
  returns 200 with its real content (`V2FixesTest.f12_pathTraversalIsBlocked`, re-confirmed manually).

## F-13 — Insecure response headers and wildcard CORS (OWASP A05:2021 Security Misconfiguration)
**Severity: Medium.** No `X-Frame-Options`, no CSP, no `X-Content-Type-Options`; `Access-Control-Allow-Origin: *`
combined with `Access-Control-Allow-Credentials: true` (a combination browsers should refuse to honour, and
a clear misconfiguration in intent); a version-revealing `X-Powered-By` banner.

- **Evidence:** ZAP's baseline (passive) scan against v1 reported 5 distinct WARN-NEW findings across 5
  response headers (`Missing Anti-clickjacking Header`, `X-Content-Type-Options Header Missing`,
  `X-Powered-By` info leak, `CSP Header Not Set`, `Cross-Domain Misconfiguration`), and the full active scan
  reported 8 total (`results/lab/zap_full_20261002T003456.html`); manually confirmed
  (`V1VulnerabilitiesTest.f13_insecureHeadersAndWildcardCors`).
- **Sentinel detection:** none directly (headers are a client-side browser protection; Sentinel protects the
  server side). Recorded here because it is a genuine, independently-tool-confirmed finding.
- **v2 fix:** `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
  `Cache-Control: no-store`, a full `Content-Security-Policy` (including explicit `base-uri` and
  `form-action`, added after ZAP's first v2 pass flagged their absence — see below), and
  `Permissions-Policy`; no CORS headers at all; no `X-Powered-By`. Re-tested: ZAP's full active scan against
  the final v2 build reports **0 WARN-NEW across 113 passive/active checks**
  (`results/lab/zap_full_20261002T005243.html`), down from 8 in v1.
  - *Honestly reported intermediate step:* the first v2 rebuild (before the CSP directive fix) still scored
    one ZAP warning, `CSP: Failure to Define Directive with No Fallback [10055]`
    (`results/lab/zap_baseline_20261002T004843.html`) — `base-uri` and `form-action` do not fall back to
    `default-src` per the CSP specification, so ZAP correctly flagged their absence. Both were added and the
    finding closed on re-scan; this is included to document the real, iterative process rather than only the
    final clean result.

## F-14 — Errors expose internals (OWASP A05:2021 Security Misconfiguration)
**Severity: Medium.** Unhandled exceptions return the full Java exception type and, in v1's global handler,
a complete stack trace.

- **Evidence:** `GET /api/orders/not-a-number` returns
  `MethodArgumentTypeMismatchException` by name in the response body
  (`V1VulnerabilitiesTest.f14_errorsExposeInternals`).
- **Sentinel detection:** overlaps F-04; verbose error text is part of what feeds SEN-002's highest-confidence
  matches when an injection payload causes a database error.
- **v2 fix:** a generic `{"error":"bad request"}` / `{"error":"internal error","reference":"<uuid>"}`, with
  the real exception and a correlation id written only to the server log. Re-tested: the same malformed
  request returns no exception name or trace (`V2FixesTest.f14_errorsAreGeneric`).

---

## Notes on scope and honesty
- Every "v2 fix" line above was re-verified against the **actual running v2 container** in this task (not
  only the pre-existing JUnit suite), by rebuilding the image, redeploying it, and re-running the same real
  attack tool or manual request used to find the v1 vulnerability.
- F-09's IDOR is **not currently covered by a Sentinel detection rule**; this gap is recorded, not hidden,
  in `docs/known-limitations.md`.
- Nmap's service/version banner (Apache Tomcat) is reconnaissance information, not one of the 14 numbered
  findings — a version banner is a platform-level hardening question (out of scope for the app-level v1→v2
  fix cycle), not something `target-shop` code can "fix" by itself.
- Numbers in this document and in the README's generated results table come only from the tool output and
  test runs cited above; nothing here was estimated or rounded up.
