# Inspect the two SSRF proofs

From the repository root, install `requests` if needed and run either mode:

```powershell
python -m pip install requests
python findings/inspect-ssrf.py datto
python findings/inspect-ssrf.py cwpsa
```

The script creates a fresh researcher-owned Webhook.site collector, verifies the response it serves, submits the control and SSRF requests with dummy integration credentials, and prints:

- Bitdefender's complete HTTP status, headers, and response body for each submission.
- Every captured server-side callback's URL, source IP, headers, and body.
- Whether a unique marker in the collector's response appears in Bitdefender's HTTP response.

It also saves the complete JSON transcript under the ignored `tmp/` directory. The transcript includes session cookies and the temporary collector URL; keep it private. To see how Bitdefender handles a different response from your collector, supply a UTF-8 file:

```powershell
python findings/inspect-ssrf.py datto --response-file .\my-response.json --response-status 200 --match my-marker
```

The default Datto response is a synthetic OAuth token, so the collector can show the follow-up GET with that same fake token. The default ConnectWise response is a synthetic company-info object. These are controlled responses from **your collector**. In the verified runs, Bitdefender did not reflect either response marker in its own HTTP response. The two SSRFs are blind with respect to an unrelated destination's response body on current evidence; the script cannot display data that the Bitdefender endpoint does not return or send to the collector.
