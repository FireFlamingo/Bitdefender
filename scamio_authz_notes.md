# Scamio two-account authorization checks — 2026-09-24 to 2026-09-26

## Result

No cross-account read or deletion was demonstrated. The backend appears to select history by the authenticated token even when the client supplies a different `userId`. Do not submit the client-side `userId` parameters as an IDOR on current evidence.

## Setup

- Used two researcher-owned Bitdefender Central accounts and exchanged their own sign-in tokens for Scamio Connect tokens. Credential and token files remain outside this repository in Windows Temp.
- Public source map: `https://scamio.bitdefender.com/main.01ea270eb5dc7d1d.js.map`.
- The source map shows `/wss` JSON-RPC `getHistory` with a client-supplied `userId`, and a `deleteMessageHistory` request to `/scamio/link-account` followed by a Socket.IO `deleteHistory` event.
- The two `current_context_id` values returned by Nimbus `getInfo` were present and distinct.
- Created one harmless, encrypted test message in account B through the public encryption API and authenticated Scamio Socket.IO `chatMessage` event. No other account's data was touched.

## Read checks

With account A's Scamio token, `POST https://scamio.bitdefender.com/wss` method `getHistory` returned an empty result for both A's and B's `userId`. With account B's token, the same method returned B's one-message history for **both** supplied IDs. Thus the supplied ID did not redirect the read to the other account.

## Delete checks

- With account A's token and B's `userId`, Nimbus `deleteMessageHistory` returned `{"success":true}`. B's one-message history remained unchanged by canonical JSON hash before and after.
- With account A's token and B's `userId`, the Socket.IO `deleteHistory` event also acknowledged `{"success":true}`. B's history still contained the message.

The success acknowledgements do not prove cross-account deletion; the observed B data was unchanged. The result is consistent with the service ignoring `userId` and applying the operation to the authenticated account.
