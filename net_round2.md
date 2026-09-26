# Bitdefender `.net` and Total Security artifact, round 2

Date: 2026-09-24 to 2026-09-26. Scope: `*.bitdefender.net` and Bitdefender Total Security. **No validated medium, high, or critical finding in this round.**

## 1. Controlled Central account authorization test

Two researcher-owned accounts supplied in local Temp files `bd_bb_account.json` and `bd_bb_account2.json` were used. Their Connect tokens were read into memory and never printed or written to this repository. The nimbus JSON-RPC endpoint and method structure came from public source map `https://nordnet-central.bitdefender.net/main.5cd22f60a73e16d2.js.map` (`connect-user-info-service.ts`).

Endpoint: `POST https://nimbus.bitdefender.net/connect/user_info`, header `x-nimbus-clientid: 2e7aaa66-0b13-46ae-b1f1-4c4c7902fcb5`, JSON-RPC 2.0. `connect_source` used each own token, `device_id: web`, `app_id: com.bitdefender.connect_mgmt`.

| Request | Outcome |
| --- | --- |
| A `profiles_list` | `status=0`, 1 own profile |
| B `profiles_list` | `status=0`, 2 own profiles (owner and child) |
| B `profiles_get` B owner | `status=0`, full own profile fields |
| A `profiles_get` B owner | `status=1`, only `status` and `data` keys |
| B `profiles_get` B child | `status=0`, full own profile fields |
| A `profiles_get` B child | `status=1`, only `status` and `data` keys |
| A `profiles_set` B child first name to test marker | `status=1`; B's own subsequent read confirmed unchanged name |

The three distinct profile IDs were verified by hash without printing them: A owner SHA256 prefix `28ff1ff3fee80246`; B owner `16c09088ce6150e5`; B child `d2c2bef3702d97d3`. No session invalidation method was used. The tested read and write authorization boundaries held.

Representative request body (substitute only the own account token and profile ID):

```json
{"id":1,"jsonrpc":"2.0","method":"profiles_get","params":{"connect_source":{"user_token":"<OWN_TOKEN>","device_id":"web","app_id":"com.bitdefender.connect_mgmt"},"profile_id":"<OWN_OTHER_ACCOUNT_PROFILE_ID>"}}
```

## 2. Public support uploader

`https://upload.bitdefender.net/` serves a custom Bitdefender React file uploader; public source map: `/static/js/main.9866612e.js.map`. The client implements anonymous upload, authenticated link generation/download, and deletion by possession of an upload link. The `Delete my files` UI intentionally accepts a `/d/{id}` link and calls anonymous `DELETE /api/upload/{id}`; this is a documented capability link, not an established vulnerability.

- `POST /api/upload/` with `{"files":[],"reCaptchaResponse":""}` returned HTTP 400 `mising challenge value or auth failure`.
- Anonymous `GET /api/auth/check`, `/api/upload/bbtest/preview`, and `/api/download/bbtest` returned 401. Anonymous status for nonexistent `bbtest` returned 404.
- OAuth2 start with attacker-chosen Base64 `state` returned 302 to the fixed Microsoft tenant with fixed `redirect_uri=https://upload.bitdefender.net/api/auth/callback`. Callback with invalid code or `error=access_denied` returned 302 to same-origin `/unauthorized`; no open redirect proved.
- Creating a self-owned upload through the browser would require solving Cloudflare Turnstile. The computer-use skill requires action-time user confirmation for CAPTCHA solving, so no browser challenge or upload was attempted.

## 3. White-label Central surface

`nordnet-central.bitdefender.net` serves a Securitoo Central frontend with a public 10 MB source map. It uses `nimbus.bitdefender.net` for JSON-RPC. In public `/download`, `first_name` and `email` from an install-code response are passed through `sanitizeValues` (entity escaping plus Angular HTML sanitization) before any HTML binding. Public `/services/parental/blocked?blocked_url=` uses Angular interpolation for the URL. No XSS established.

Source map has a Google Maps API key and Sentry DSNs, which are public client values and do not meet the program's reward criteria. Unauthenticated `get_login_token` with empty token returned JSON-RPC data code `1001` / `Invalid token`; `decode` with a random nonexistent install code returned `share link missing`.

## 4. Total Security installer static assessment

Official online installer: `https://download.bitdefender.com/windows/installer/en-us/bitdefender_tsecurity.exe`; 22,557,608 bytes; SHA256 `feb7315ad9a1c4158b2dadd59c36c2646521159ed72352a9714a26074b2f5672`. The installer is a RAR5 SFX containing `agent_launcher.exe`, `bddeploy.exe`, `deploy.dll`, `agentpackage.exe`, and `setuppackage.exe`. All five embedded PE files returned valid Bitdefender Authenticode signatures. The package contains MD5 manifest files; `bddeploy.exe` contains strings for archive integrity and signature checks.

The extracted agent configuration points to HTTPS nimbus and HTTPS update endpoints. `ProductAgent.json` names `https://download.bitdefender.com/windows/desktop/connect/cl/2016/update.json`, whose current response contains an HTTPS signed update executable URL, MD5, and version. A hardcoded HTTP version of this metadata URL also appears in some binary strings, but the active path and signature verification behavior were not established. No supply-chain exploit or local code-execution primitive was demonstrated. The artifact was inspected statically in the local Temp directory; it was not executed or installed.
