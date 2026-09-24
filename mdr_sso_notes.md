# MDR stage SSO `idpMetadataUrl` check — 2026-09-23 UTC

## Conclusion

No pre-auth SSRF or open redirect was demonstrated. Supplying an external metadata URL changes the response from the normal GravityZone discovery redirect to a same-origin SSO error redirect. A controlled OAST endpoint recorded **zero** requests from the target after several variants. Do not submit this as a vulnerability on current evidence.

## Client code and reachable parameter

- `tmp/mdr_chunk-77KY2YWE.js` contains `initiateSsoLogin(e,n,i,r)`: it adds `idpMetadataUrl=i`, `idpRegion=n`, and `forceGravityZoneSso=r.toString()` to the query string, then navigates to `/v2/users/sso/initiate-sso-login`.
- `tmp/mdr_main-472XBVCC.js` accepts `idpUrl`, `email`, and `region` from the app page's query string. If `idpUrl` or `email` is present, it calls `initiateSsoLogin(email, region, idpUrl, true)`.
- Thus a pre-auth browser navigation can supply `idpMetadataUrl`; the server's use of it had to be validated separately.

## Controlled endpoint

- Created a disposable Webhook.site token using `POST https://webhook.site/token`, ID `aa815d26-441a-41b3-937b-a6d78d7de5cd`, with HTTP 200 plain-text response.
- Used `aa815d26-441a-41b3-937b-a6d78d7de5cd@email.webhook.site` as the test email address. No external customer email address or private network target was used.
- A control `GET https://webhook.site/aa815d26-441a-41b3-937b-a6d78d7de5cd/control` appeared in the token request log as the **only** recorded request. This confirms the OAST capture and read API were working.

## Requests and results

All requests were GET with redirects disabled (`curl -i` without `-L`).

| Case | Query parameters | Response |
| --- | --- | --- |
| No IdP params | `forceGravityZoneSso=false` | HTTP 400 `no_idp_region_metadata` / `Missing IdP params for SSO login` |
| External metadata URL | `idpMetadataUrl=https://webhook.site/<token>/mdr-first&forceGravityZoneSso=false` | HTTP 302 to `https://app-stage.mdr.bitdefender.com/sso-error?errorCode=1...` |
| Force GZ | `idpMetadataUrl=https://webhook.site/<token>/mdr-true&forceGravityZoneSso=true` | Same-origin SSO error 302 |
| Owned email | `email=<token>@email.webhook.site&idpMetadataUrl=https://webhook.site/<token>/mdr-email&forceGravityZoneSso=true` | Same-origin SSO error 302 |
| Region | Same as above, with `idpRegion=eu` and metadata URL path `/mdr-region.xml` | Same-origin SSO error 302 |
| Scheme-relative URL | Owned email and `idpMetadataUrl=//webhook.site/<token>/mdr-scheme-relative&forceGravityZoneSso=true` | Same-origin SSO error 302 |
| Baseline, no metadata URL | Owned email, `idpRegion=eu&forceGravityZoneSso=true` | HTTP 302 to `https://gravityzone.bitdefender.com/discovery?return=https://app-stage.mdr.bitdefender.com/v2/users/sso/discovery-response` |
| Baseline, no metadata URL or region | Owned email, `forceGravityZoneSso=true` | Same GravityZone discovery 302 |

After the metadata URL requests, `GET https://webhook.site/token/<token>/requests?sorting=newest` returned `total=0`; after the control request it returned `total=1`, containing only `/control` and no `/mdr-*` path. No response redirected to the controlled Webhook.site URL.

## Limit

The server returns only a generic SSO error for arbitrary external metadata URLs, so the exact internal validation condition is unknown. This test rules out a direct fetch or redirect to the controlled URL in the tested pre-auth flows; it does not prove how a configured tenant's legitimate IdP metadata is processed.
