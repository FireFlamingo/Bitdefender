# Central/Nimbus two-account authorization review (2026-09-24 to 2026-09-26)

**Result:** No cross-account access or privilege change was confirmed. All probes used only two researcher-owned Central accounts, A and B. Credentials and tokens remain outside the repository in `C:\Users\amogh\AppData\Local\Temp\bd_bb_account.json` and `bd_bb_account2.json`. The current Central frontend bundle reviewed was `https://central.bitdefender.com/main.f050c81d3b8be5de.js`.

## Owned test setup

- A and B each activated a no-payment Total Security Individual trial. Service IDs: A `b10bdfd7-f32a-4bb4-ae2e-b07010273c38`; B `4168de03-4b98-4e39-b0cd-907540644e63`. Both have `max_shares: 0`.
- A and B each activated a no-payment SecurePass one-month trial. Service IDs: A `71398da3-ab97-4da8-a7f4-31f2a5b51c1b`; B `d64d4acc-befd-4495-bbcf-858169344ac2`. These have one slot and no shareable entitlement in the trial metadata.
- B created a fictional child profile `0cbbe046-8443-46d4-85b3-d845e3f78550` to test the parental data boundary. Its own contact list was empty and its own location feature state was `true`.
- A and B's primary context IDs were `6776a596-7fc4-46a6-a7f2-245153a74afe` and `6fb4ee4e-cdee-461d-b136-f0f7d64a9643` respectively.

All Nimbus examples below use JSON-RPC 2.0 over HTTPS with a `connect_source` containing the caller's own `user_token`, `device_id: "web"`, and `app_id: "com.bitdefender.connect_mgmt"`. No token value is included here.

## Session and context boundaries

1. `POST https://nimbus.bitdefender.net/connect/login` with method `switch_context`, A's token, and B's `context_id` returned `error.data.code: 1021`, `Context not available!`. Switching A to its own current context returned code 1022, `Already in this context!`.
2. `POST https://nimbus.bitdefender.net/connect/connect_mgmt` with method `list_sessions` returned one active session for each caller. A's attempt to `close_session` using B's session ID `51b12afd-8804-494c-a042-46ba61c7dbef` returned code 32801, `Communication error!`; B's session remained in B's list and B remained authenticated.
3. B created a second own session and, from that session, called `close_session` on B's old session ID. It returned `{"result":{"status":0}}`; B's next `list_sessions` omitted the old session. This own-account control confirms that the method can close a valid session, whereas the cross-account call did not.

## Profile and parental data boundaries

- `POST https://nimbus.bitdefender.net/connect/user_info` method `profiles_get` returned `status:0` for each caller's own profile and `{"status":1,"data":"Profile not found!"}` for the other account's primary profile, in both directions.
- Method `profiles_set` with A's token and B's primary `profile_id`, changing only `first_name`, returned `{"status":1,"data":"Profile not found!"}`; B's profile was unchanged.
- Method `profiles_set` with A's own `profile_id` but B's `user_id` added returned JSON-RPC code 32001, `Additional properties not allowed`; neither account's name changed.
- Method `getInfo` with A's token and an extra B `context_id` returned code 32001, `Additional properties not allowed`.
- `POST https://nimbus.bitdefender.net/parentalcontrol/contacts` method `get` for B's child profile and fields `["list","state_feature"]` returned `{"list":[],"state_feature":true}` to B; A received `Issue occurred regarding profile ownership`.
- `POST https://nimbus.bitdefender.net/parentalcontrol/location` method `get` for B's child profile and field `state_feature` returned `{"state_feature":true}` to B; A received the same ownership error. A's `edit` request with `state_feature:false` also received that error, and B's own follow-up read remained `true`.

## Trial, invitation, group, and renewal boundaries

- `POST https://nimbus.bitdefender.net/subscribe/invite_system` method `create_invite`: A using A's Individual trial to invite B returned code 32608, `Subscription/license cannot be shared`. B using A's service ID returned code 39001, `This service does not exist or you do not have invite rights!`. No invitation was created.
- `POST https://nimbus.bitdefender.net/connect/group_mgmt` method `create_group` with A's trial ID, `group_type:"family"`, and `group_label:"Research Family"` returned code 39117, `The subscription bundle is not valid for groups`. Without a `service_id`, schema validation failed. No group was created, so group-role escalation could not be exercised with these trials.
- `POST https://connect.nimbus.bitdefender.net/connect/renewal_info` method `get_upgrade_link` with own and other-owned trial service IDs returned the same code 32801, `Error retrieving upgrade link`, across both accounts. This is inconclusive for authorization because the own-account control did not succeed.
- `POST https://nimbus.bitdefender.net/connect/renewal_info` method `get_single_sign_on` with own and other-owned trial service IDs returned code 39001, `Subscription not found`, including for own trial. This is also inconclusive for a paid-subscription SSO boundary.

## Credentialed CORS check

- `OPTIONS` and authenticated `POST https://nimbus.bitdefender.net/connect/user_info` from `Origin: https://attacker.example` returned `Access-Control-Allow-Origin: *` and **no** `Access-Control-Allow-Credentials`. The RPC requires the `user_token` inside the JSON body, so this did not yield a credentialed cross-origin read without already knowing the token.
- `POST https://account.bitdefender.com/v1/account/info` from `Origin: https://attacker.example` returned no `Access-Control-Allow-Origin` or `Access-Control-Allow-Credentials` headers. No readable account-data PoC was found.

## Cross-product SSO audience check (2026-09-26)

Using A's own, freshly issued Central sign-in JWT (`aud: central.bitdefender.com`) against GravityZone's Ext RPC endpoint:

```http
POST /webservice/CCORE/system HTTP/1.1
Host: cloud.gravityzone.bitdefender.com
Content-Type: application/json

{"action":"SecurityManager","data":{"jwtToken":"<A's Central JWT>"},"type":"rpc","method":"authenticateWithBearer","tid":1}
```

The service returned `{"type":"exception","message":"Authentication failed","exceptionType":"Exceptions\\AuthenticationFailed"}`; a same-session `getUserInfo` still returned `result:null`. `authenticateWithToken` with the same Central JWT likewise returned `AuthenticationFailed`. The consumer JWT did not authenticate to GravityZone.

## Temporary-token context confusion check

`connect/login.get_login_token` with A's Nimbus token returned a new opaque 36-character `user_token` in each call. Adding B's context ID either as a top-level `context_id` or within `connect_source` did not cause an immediate error, but token values alone do not prove an identity change. All three tokens, including the own-account control, were rejected by `connect/login.connect` as code 1017, `Invalid partner user token`. No cross-account session was established. The temporary-token flow may serve a different frontend purpose; its effect on account SSO was not established.

## Practical limit

The two no-payment subscriptions do not allow sharing or family groups, and have no linked devices, payments, invoices, or other users. The high-value device, paid-renewal SSO, and shared-group authorization paths therefore lack a successful own-account control and were not claimed as vulnerable. No third-party account or data was accessed.
