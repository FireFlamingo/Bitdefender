# `*.bitdefender.net` investigation — 2026-09-23

## Result

No reproducible medium-or-higher issue found on the assessed `.net` surfaces. The LEAP search frontend has an unescaped HTML sink, but an authenticated search response and attacker-controlled indexed content are needed to establish a working XSS PoC. Do not submit it as a finding on current evidence.

## Scope and methods

- Read `scope.txt`; `.net` wildcard is included and third-party software bugs, descriptive errors, old versions, and theoretical issues are non-rewardable.
- Enumerated certificate transparency names through crt.sh and Cert Spotter, then checked selected DNS CNAMEs and a small set of HTTP GET/HEAD routes. No customer data was retrieved or changed.
- Inspected public JavaScript and source maps for four LEAP frontends. Tested only unauthenticated API access and one invalid `alg:none` JWT against read-only routes. No authorization bypass occurred.

## Candidate: LEAP search result HTML sink (unvalidated)

- Public artifact: `https://darknet.leap.bitdefender.net/static/js/main.cc1dfb03.js.map`.
- `components/results/Results.jsx` lines 289–294 and 310–317 insert `results[i][j].text.join().replace(/--->>>(.*?)<<<---/g, '<b>$1</b>')` into `dangerouslySetInnerHTML`, without an evident client-side sanitizer.
- The frontend obtains results from `https://uti-api.leap.bitdefender.net/v2/search`, according to the compiled bundle.
- `GET /v2/search?q=example.com` without a token returned `401 {"error":401,"error_message":"No Authorization header"}`. A syntactically valid `alg:none` test JWT returned `401 Unauthenticated`.
- LEAP SSO registration is unavailable: the Keycloak registrations route for client `athena-frontend` returned HTTP 400 with `Registration not allowed`. The login page exposes no signup link. An unauthenticated researcher cannot confirm whether the backend returns attacker-controlled HTML text in search results.
- A potential outcome, **if** the backend preserves attacker-controlled HTML in indexed snippets, is stored XSS in the authenticated LEAP origin. This condition has not been proven live.

## Other LEAP boundary checks

- `lea-api.leap.bitdefender.net/api/v1/getUsers`, `/getOrgs`, `/getFeedbacks`, `/getTypes`, and `/getNotifications` returned 401 without bearer token; `alg:none` JWT returned 403.
- `athena-api.leap.bitdefender.net/api/v1/admin/users`, `/api/v1/user/cases`, and `/api/v1/user/microservices` returned 401 without bearer token. `alg:none` JWT returned 401.
- `invite-api.leap.bitdefender.net/api/v1/invites` returned an error for missing or invalid auth. `timetravel.leap.bitdefender.net/pp/api/v1/url_shortener` returned `No auth header`.
- Keycloak client `athena-frontend` rejected `redirect_uri=https://example.com/cb` with HTTP 400.
- Public source maps reviewed for `leap`, `athena.leap`, `darknet.leap`, and `timetravel.leap`. No hard-coded AWS, Google, GitHub, Slack, Stripe, private key, JWT, or Basic auth literal matched the tested patterns.

## DNS and other services

- Checked CNAMEs from roughly 130 certificate-transparency hostnames. External targets were active AWS ELB, Cloudflare CDN, and Akamai edges. No dangling third-party alias was established. `leap.bitdefender.net` is delegated to `bob.ns.cloudflare.com` and `bella.ns.cloudflare.com`, both active.
- Placeholder-looking CDN names `patches-please-change-me.cdn.bitdefender.net` and `upgrade-please-change-me.cdn.bitdefender.net` returned HTTP 200 on both HTTP and HTTPS. No unclaimed service fingerprint was observed.
- `registry.leap.bitdefender.net` is Nexus Repository. Anonymous `/service/rest/v1/repositories` returned `[]`; `/service/rest/v1/security/users` and `/v2/` required authentication. No Bitdefender configuration flaw established.
- `flow.bitdefender.net` returned 404 on `/` and standard docs/health paths. `connect.bitdefender.net/realcheck` returned `Report Not Found` without a report ID. No sensitive report was accessed.

## Reproduction references

```text
GET https://darknet.leap.bitdefender.net/static/js/main.cc1dfb03.js.map
GET https://uti-api.leap.bitdefender.net/v2/search?q=example.com
GET https://sso.leap.bitdefender.net/auth/realms/lea/protocol/openid-connect/registrations?client_id=athena-frontend&response_type=code&scope=openid&redirect_uri=https%3A%2F%2Fleap.bitdefender.net%2F
```
