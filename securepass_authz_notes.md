# SecurePass two-account vault authorization checks — 2026-09-26

## Result

No cross-account vault read, write, or object creation was demonstrated. All state changes used two researcher-owned trial accounts and harmless test data.

## Setup

- Activated a no-payment SecurePass trial on each of two owned Central accounts.
- Exchanged each account's own Central sign-in token for a SecurePass Connect token, then used the web client's public JSON-RPC protocol at `securepass-auth-rpc.bitdefender.com/connect/loki-auth` to set separate random master passwords and activate each vault. Crypto keys, tokens, and passwords are only in the current user's Windows Temp directory, outside Git.
- Created one datastore for each account with a distinct random encryption key. Account B then created one encrypted note containing only the marker “Owned bounty vault probe.”
- The public web bundle and `https://securepass.bitdefender.com/config.json` supplied the API base URL and client protocol. No password-manager UI was automated.

## API boundary checks

All direct vault API requests used `Authorization: Token <own SecurePass token>`, an encrypted `Authorization-Validator`, and the caller's own session key. Account B's own read decrypted the test note and matched the original harmless content.

| Request | Result |
| --- | --- |
| B `GET /secret/{B test secret ID}/` | HTTP 200; decrypted note matched B's marker |
| A `GET /secret/{B test secret ID}/` | HTTP 400 `non_field_errors` |
| B `GET /datastore/{B datastore ID}/` | HTTP 200 |
| A `GET /datastore/{B datastore ID}/` | HTTP 403 |
| A `POST /secret/` to overwrite B's secret | HTTP 400 `NO_PERMISSION_OR_NOT_EXIST`; B's ciphertext and nonce remained unchanged |
| A `POST /datastore/` to change B's datastore description | HTTP 400 `DATASTORE_NOT_EXIST`; B's description remained unchanged |
| A `PUT /secret/` with B's datastore as parent | HTTP 400 `PARENT_DATASTORE_NOT_EXIST` |

The own-account controls succeeded and the cross-account operations were denied. No password disclosure, vault modification, or account takeover was established.
