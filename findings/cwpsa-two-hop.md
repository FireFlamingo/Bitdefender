# ConnectWise PSA two-hop SSRF and response reflection (2026-09-28)

**Status:** Verified with researcher-owned destinations. Security impact beyond an unconfigured synthetic integration is unproven; no Medium-or-higher bounty claim is made.

## Reproduction

Run [`cwpsa-two-hop-poc.py`](cwpsa-two-hop-poc.py) from the repository root:

```powershell
python findings/cwpsa-two-hop-poc.py
```

The script creates two disposable HTTPS collectors and supplies only dummy ConnectWise API keys. The first collector serves a company-info object with `IsCloud: true`, `Codebase: "v4_6_release/"`, and `SiteUrl` set to the second collector. The second serves a JSON array containing a unique owned marker.

Observed path:

1. An anonymous `POST /login` with the first collector as `ManageUrl` causes Bitdefender to issue `GET /login/companyinfo/<owned company>` to it.
2. Bitdefender trusts `SiteUrl` from that response and issues `GET /v4_6_release/apis/3.0/company/companies?page=1&pageSize=1` to the second collector. The login-check Basic header contains only the submitted dummy company ID and API keys.
3. The JSON array response causes `POST /login` to redirect to `/` and set `.AspNetCore.Cookies`. An anonymous `GET /` redirects to `/login`; the same-session `GET /` returns the app HTML.
4. Same-session `GET /api/PluginConfiguration/serviceBoards` triggers `GET /v4_6_release/apis/3.0/service/boards?pageSize=1000&conditions=projectFlag=false%20AND%20inactiveFlag=false` to the second collector. Bitdefender returns HTTP 200 with the owned marker in its JSON response. This is verified response reflection, not merely a blind callback.

The second-hop requests came from `20.111.12.174` in the observed runs. The service-board request also sent a Basic header; its password portion was an opaque 344-character Base64 string, unlike the plaintext dummy key sent during the login check. Its origin and meaning are unverified, so it is not claimed as a Bitdefender secret. The full live transcript stays under ignored `tmp/` and includes temporary session cookies.

A [sanitized evidence snapshot](cwpsa-two-hop-evidence.json) records the callback paths, the reflected owned marker, and the redirect and loopback controls without cookies or collector management tokens.

## Redirect, transport, and internal reach checks

Using a temporary researcher-owned HTTPS responder, the service-board endpoint followed a 302 to a different owned HTTPS origin and returned that origin's JSON marker. The cross-origin redirected request did **not** carry the Basic authorization header. A 302 to an owned HTTP collector produced no callback. This confirms a cross-origin HTTPS response-reflecting redirect, while HTTP downgrade remains unproven.

The same responder redirected to `https://127.0.0.1:1/` and `https://127.0.0.1:443/`. Both Bitdefender API calls returned HTTP 500 `An exception was thrown.` in about two seconds. Direct `SiteUrl` tests of loopback ports 1, 443, 8443, and 5001 similarly ended at `/Error`. The closed-port control and tested ports were indistinguishable; no reachable internal service or useful port oracle was established.

`SiteUrl` selected the second-hop HTTPS host, while its path, query, and fragment were ignored. `Codebase` dot segments changed the path prefix, but the client still appended its ConnectWise API path; `?` and `#` in `Codebase` were percent-encoded. A first-hop response-code oracle distinguished a 200 owned response from a 404. A second-hop shape oracle distinguished a 200 JSON array (session issued) from JSON object/string and HTTP 404 (login error). Neither oracle revealed response bytes from an internal destination.

## Impact boundary

The synthetic session only reached the initial configuration flow. `GET /api/PluginConfiguration/serviceBoards` reflected the owned response; `GET /api/standalone/userinfo` returned HTTP 500, and other configuration reads mostly returned HTTP 500 or empty data. A dummy GravityZone registration/check request returned HTTP 500 before contacting the owned GravityZone mock. [Bitdefender's integration guide](https://www.bitdefender.com/business/support/en/77211-1067516-configuring-the-integration.html) says a GravityZone Partner API key and access URL are needed to link a PSA tenant, and the initial wizard disables other menu options until configuration completes.

No existing tenant, customer record, database, or internal endpoint was read or changed. To make this bounty-ready under the [current program](https://www.bitdefender.com/en-us/site/view/bug-bounty), a follow-up must demonstrate a protected read/write or another concrete security consequence, preferably with a researcher-owned registered tenant.
