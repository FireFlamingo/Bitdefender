# Bitdefender Central and GravityZone web review (2026-09-23)

Scope reviewed: `central.bitdefender.com`, `login.bitdefender.com`, `nimbus.bitdefender.net` (Central backend), `gravityzone.bitdefender.com`, and `cloud.gravityzone.bitdefender.com`. No medium or higher vulnerability was confirmed in the unauthenticated checks below. This is a bounded review, not a claim of security for these services.

## Central authentication and API boundary

- `GET https://central.bitdefender.com/` served Angular build `main.f050c81d3b8be5de.js`. Its RPC calls to `https://nimbus.bitdefender.net/connect/user_info` carry `connect_source.user_token`.
- Anonymous request:

  ```http
  POST /connect/user_info HTTP/1.1
  Host: nimbus.bitdefender.net
  Content-Type: application/json

  {"id":1,"jsonrpc":"2.0","method":"getInfo","params":{"connect_source":{"user_token":"","device_id":"central-web","app_id":"central-web"}}}
  ```

  Response: HTTP 200 with `{"error":{"code":32004,"message":"Wrong credentials"}}`.
- The login UI calls `POST https://login.bitdefender.com/v3/ui` with `partner_id` and `redirect_url`. The default `https://central.bitdefender.com/dashboard` returned `{"ui":"central"}`. External `https://example.org/`, host suffix `https://central.bitdefender.com.evil.example/`, userinfo confusion `https://central.bitdefender.com@example.org/`, and percent-encoded dot variants each returned HTTP 401 `InvalidRedirectUrl`. No redirect validation bypass was found.

## GravityZone authentication and login surface

- Anonymous `POST https://cloud.gravityzone.bitdefender.com/api/v1.0/jsonrpc/accounts` with `getAccountList` returned HTTP 401: "Authorization header not passed, HTTP Basic Authentication should be used."
- Anonymous `POST https://gravityzone.bitdefender.com/api/v1.0/jsonrpc/accounts` returned HTTP 401: "Invalid API key. Please generate an API key in Control Center."
- Anonymous `SecurityManager.getUserInfo` on `POST https://gravityzone.bitdefender.com/webservice/CCORE/system` returned `result:null`.
- `SecurityManager.getAvailabilityZones` for `test@example.com` returned a fixed zone name, `GravityZone Cloud Instance 2`, and a fixed `cloud.gravityzone.bitdefender.com` URL. Its login page inserts the returned zone name and URL through `.html(...)`; I found no path for an external user to control these strings, so this is not a validated XSS.
- `SecurityManager.validateReturnParameter` with `returnUrl` set to both `https://cloud.gravityzone.bitdefender.com/` and `https://example.org/`, and `serverUrl` set to `https://cloud.gravityzone.bitdefender.com/`, returned `result:false` for both. The `/discovery?return=` path invokes this validation before redirecting.
- `GET https://cloud.gravityzone.bitdefender.com/webservice/HTML/system/SecurityManager/renderTwoFactorBackupPage` without the required `secret` parameter produced a descriptive error (explicitly non-rewardable); a form `POST` with a harmless marker in `secret` returned HTTP 403. No unauthenticated reflection was found.

## Remaining lead

With an authorized test account, inspect whether `renderTwoFactorBackupPage` HTML-escapes the posted `secret` and enforces CSRF. Anonymous requests are blocked at HTTP 403, so the current evidence does **not** support a report. Also test any tenant-owned GravityZone SSO metadata names before claiming the login `.html(...)` sink is controllable across tenants.
