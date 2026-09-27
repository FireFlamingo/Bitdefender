# Bitdefender bounty research, 2026-09-27

## Program scope and decision rule

The [current Bitdefender bounty page](https://www.bitdefender.com/en-us/site/view/bug-bounty) adds `*.meshsecurity.io` and `*.emailsecurity.app` to the older `scope.txt` snapshot. It lists pre-authentication account takeover as non-rewardable and requires a working proof of a meaningful security boundary crossing. The existing Datto RMM and ConnectWise PSA SSRF reports remain valid observations, but their earlier Medium scores assumed an unproven integrity impact. They are unrated and not bounty-ready until an additional consequence is demonstrated.

## SSRF chain check

The earlier ConnectWise PSA proof shows an unauthenticated, arbitrary HTTPS GET from `cwpsa.rmm.bitdefender.com` to an owned collector. I returned a plausible ConnectWise company-info JSON object from that collector (`CompanyName`, `Codebase`, `VersionCode`, `VersionNumber`, `CompanyID`, `IsCloud`). A new login attempt with dummy integration credentials returned HTTP 302 to `/Error`. The collector saw two GETs to `/login/companyinfo/<owned marker>` and no later request. This did not establish a Bitdefender session, protected API access, credential disclosure, or an account takeover. The Datto mock result remains bounded by `findings/datto-chain-bounds-2026-09-26.md`.

## Other in-scope surfaces

| Surface | Read-only check | Result |
| --- | --- | --- |
| CSRTools API | Anonymous `GET /v1/account/me` | HTTP 401 `Token not provided`. Frontend auth routes returned 404 on direct POST with an empty body; no authenticated path or bypass was established. |
| MSP and beta MSP API | Anonymous reads of organizations, business users, keys, client credentials, data events, and tasks | Sensitive list endpoints returned HTTP 401. Tasks returned HTTP 400 without pagination and HTTP 401 with `page=0&limit=10`. |
| Mesh/emailsecurity | Certificate-transparency and DNS review; one shallow root request per discovered live host | The documented `hub-us.emailsecurity.app` and `hub-eu.emailsecurity.app` portals returned Azure gateway 403. Most old Mesh development/admin names did not resolve or connect. Public docs/status/marketing sites were live; no tenant API was exposed. |
| Horangi | Certificate-transparency review and shallow root requests on selected app, API, auth, analytics, and admin names | `app.horangi.com` redirects to GravityZone; `id.horangi.com` redirects to Bitdefender business. Selected API, auth, GitLab, Metabase, and portal names did not connect. No database or tenant data was accessed. |
| Remote assistance | Root response on `ra*.bitdefender.com` | Cisco VPN login page. No Bitdefender application endpoint was found. |

The public JavaScript bundles reviewed in this pass did not contain a matching literal AWS access key, GitHub/GitLab token, Stripe live secret, private key, JWT, or Basic authorization value. This is a bounded pattern scan, not a full secret audit.

## Status and strongest remaining path

No account takeover, remote code execution, database access, or newly bounty-ready Medium-or-higher finding was verified in this pass. The best remaining path is a two-tenant GravityZone or MSP authorization review, especially device commands, SSO, and tenant-scoped administration. The two existing owned consumer trials do not grant GravityZone business access. The current GravityZone trial signup requires a business email, company, and phone number, so no business tenant was created from invented contact details.
