# Independent review of Datto RMM SSRF (2026-09-24)

Reviewed [`findings/datto-ssrf.md`](findings/datto-ssrf.md) and [`findings/datto-ssrf-poc.py`](findings/datto-ssrf-poc.py) against the [current Bitdefender program](https://www.bitdefender.com/en-us/site/view/bug-bounty).

## Independent reproduction

- Created a fresh Webhook.site collector with an HTTP 200 JSON response containing only a made-up access token.
- Sent unauthenticated `POST https://datto.rmm.bitdefender.com/api/user/signIn` with dummy API credentials and `rmmServerAddress` set to `https://<my-token>.webhook.site/probe?marker=review-61dab29aa1#x.centrastage.net`.
- Target returned HTTP 404 `ERR2`. The collector captured an OAuth POST and subsequent GET to the exact `/probe?marker=review-61dab29aa1` path/query from `74.234.78.221`. The POST body was `username=invalid-review-probe&password=invalid-review-probe&grant_type=password`, with `Authorization: Basic cHVibGljLWNsaWVudDpwdWJsaWM=`. The GET used `Authorization: Bearer review-test-token`, which the collector itself had supplied.
- A control using the same collector without `#x.centrastage.net` returned HTTP 400 and generated no callback. `http://` with the fragment also returned HTTP 400 and generated no callback. Only arbitrary **HTTPS** destinations were demonstrated.

## Scope and claim audit

- `datto.rmm.bitdefender.com` is covered by `*.bitdefender.com` and is absent from the program's named excluded-host list. The finding concerns Bitdefender's integration API, rather than a flaw in third-party Datto software.
- The unauthenticated server-side request is reproducible and supports **CWE-918**. The attacker chooses origin, path, and query for an HTTPS POST. A response containing a made-up OAuth access token triggers a follow-up GET with that token.
- No internal destination, cloud metadata access, target data disclosure, victim credential exfiltration, protected API access, or state change was demonstrated. The OAuth username/password and subsequent bearer token observed by the collector were attacker supplied. The report correctly disclaims these outcomes.
- The report's **Medium / CVSS 5.3** assessment uses `I:L`; integrity impact beyond making a request to the researcher's own HTTPS collector is unproven. Treat severity as provisional and avoid implying the CVSS vector is fully evidenced. The program explicitly requires a meaningful security consequence and excludes impact based solely on theory (policy lines 381-390 and 414-418). Acceptance as a medium bounty is therefore uncertain on the current proof.
- The public `pages/Login.js` source map has a client-side URL regex that permits `#` before `.centrastage.net`. It does **not** permit `/path?query` before the fragment, whereas the API did accept that request. It illustrates a related validation pattern but does not reveal the server's exact implementation. Avoid presenting it as direct proof of backend root cause.
- The program's submission requirements ask for the affected product/platform/version. For this hosted integration, specify the live service and observation date; mark version unavailable if no build identifier can be obtained, rather than inventing one.

## PoC review

The attached PoC creates its own collector, sends one control and one probe with dummy credentials, polls for the callback, and checks the marker in the POST body. It is reproducible and avoids tenant-registration writes. It should keep the current caveat that the observed impact is arbitrary server-side HTTPS egress; further claims require a demonstrated trust-boundary effect.

## Redirect follow-up (owned collector, no internal targets)

- Confirmed directly that `https://httpbin.org/redirect-to?url=<encoded-owned-collector>&status_code=302` returned an HTTP 302 with the intended `Location` before using it in `rmmServerAddress`.
- For a 302 to `http://<owned-collector>/redirect-test?marker=redirect-1554961a6c`, the Datto sign-in returned HTTP 400 `Invalid Datto RMM credentials.` The collector recorded **no** request with that marker. This does not distinguish a refused HTTP downgrade from an outbound port-80 restriction or another HTTP-path failure.
- For an otherwise identical 302 to `https://<owned-collector>/redirect-test?marker=redirect-https-fe6ca4e410`, the Datto sign-in returned HTTP 404 `ERR2`. The collector recorded two GETs from `74.234.78.221` at the redirected path/query. One is consistent with the OAuth POST's HTTP 302 changing method to GET; the second is consistent with the subsequent bearer-token GET being redirected as well. Neither request carried an `Authorization` header or body after the cross-origin redirect.
- Conclusion: **cross-origin HTTPS redirects are followed**. This expands the arbitrary HTTPS destination proof but does not establish HTTP downgrade, credential leakage across redirects, internal reachability, or a higher severity.
