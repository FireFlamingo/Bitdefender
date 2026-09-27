# Unauthenticated server-side request forgery in ConnectWise PSA sign-in

| Field | Assessment |
| --- | --- |
| Severity | Provisional Medium, CVSS 3.1 **5.3** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`); the integrity rating depends on the reachable destination's handling of the forced GET. |
| CWE | CWE-918, Server-Side Request Forgery |
| OWASP | A10:2021, Server-Side Request Forgery |
| Affected component | `POST https://cwpsa.rmm.bitdefender.com/login` (hosted integration, observed 2026-09-24 UTC; backend user agent identifies build `1.0.9743.31067`) |

`cwpsa.rmm.bitdefender.com` is covered by `*.bitdefender.com` and is not a named excluded host. The issue is in Bitdefender's ConnectWise PSA integration flow, rather than a flaw in ConnectWise software.

## Summary

The public login form accepts an arbitrary `ManageUrl` and contacts it **before** validating the supplied ConnectWise credentials. With a researcher-owned HTTPS URL and dummy keys, the Bitdefender server made GET requests to the supplied host. The URL does not need a `myconnectwise.net` suffix or fragment; both a plain external URL and one ending in `#x.myconnectwise.net` produced callbacks.

The server builds a request path from `ManageCompanyId`. Dot segments in that field were normalized by the HTTP client, allowing the unauthenticated caller to select a different path on the destination host. The test used only an owned collector. No private-network target, other tenant, or user data was accessed.

## Reproduction

1. Create an HTTPS request collector. The attached PoC creates a temporary Webhook.site URL and polls its own request log.
2. `GET /login` on `cwpsa.rmm.bitdefender.com` and retain the session cookie and hidden `__RequestVerificationToken` field.
3. In the same session, submit a login form with dummy credentials:

```http
POST /login HTTP/1.1
Host: cwpsa.rmm.bitdefender.com
Content-Type: application/x-www-form-urlencoded
Cookie: <cookie from GET /login>

SsoAlias=&ManageUrl=https%3A%2F%2F<owned-collector>.webhook.site&ManageCompanyId=direct-test&ManagePublicKey=codex-test&ManagePrivateKey=codex-test&__RequestVerificationToken=<token from GET /login>
```

4. The login POST redirects to `/Error` because the dummy credentials do not identify a valid ConnectWise tenant. The collector nevertheless receives a request such as:

```http
GET /login/companyinfo/direct-test HTTP/1.1
Host: <owned-collector>.webhook.site
User-Agent: Bitdefender.HttpClient/1.0.9743.31067
```

In a verified run at `2026-09-24 06:26:28 UTC`, the callback came from `20.111.12.174` to the owned collector. No valid ConnectWise account or Bitdefender session was used.

5. To demonstrate path control, repeat the request with `ManageCompanyId=../../path-test`. The owned collector receives `GET /path-test` rather than the usual `/login/companyinfo/...` path. The verified callback at `06:26:29 UTC` came from the same source IP. The attached PoC runs both safe variants with unique markers.

A sanitized snapshot of the two collector events is in [`cwpsa-ssrf-evidence.json`](cwpsa-ssrf-evidence.json). The independently observed fragment-suffixed URL `https://<owned-collector>.webhook.site#x.myconnectwise.net` also produced a callback, but the plain URL demonstrates that the fragment is unnecessary.

For a full live request/response transcript using a disposable owned collector, run [`inspect-ssrf.py`](inspect-ssrf.py) with `cwpsa` as described in [`inspect-ssrf.md`](inspect-ssrf.md). It prints Bitdefender's HTTP response and the collector's inbound requests, then saves the raw event JSON outside Git.

## Impact and limits

An unauthenticated caller can induce the ConnectWise PSA integration to make HTTPS GET requests to an arbitrary host, with control over the normalized path, from the service's network context. The callback proves the server-side request and absence of an authentication prerequisite. The test did not establish access to internal HTTPS hosts, reflection of response bodies, target state changes, victim credential disclosure, or account takeover. The submitted integration keys were dummy values. Acceptance and severity therefore depend on the program's assessment of the demonstrated request capability; the CVSS integrity rating is provisional.

## Remediation

Validate the parsed `ManageUrl` before any outbound request. If only ConnectWise hosted tenants are supported, use an exact or strict hostname allowlist. If custom or on-premises tenant URLs are required, isolate this pre-authentication fetch from private, loopback, and link-local networks; revalidate DNS results and redirects; and apply a narrow egress policy. Treat `ManageCompanyId` as an opaque identifier with an allowlist of valid characters so dot segments cannot alter the constructed path.
