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

The default Datto response is a synthetic OAuth token, so the collector can show the follow-up GET with that same fake token. The default ConnectWise response is a synthetic company-info object. These are controlled responses from **your collector**. In the immediate login responses tested by this script, Bitdefender did not reflect either response marker. Datto remains blind on current evidence; ConnectWise has a separate response-reflecting second hop described below.

For the ConnectWise two-hop path, use [`cwpsa-two-hop-poc.py`](cwpsa-two-hop-poc.py). It demonstrates response reflection from a second owned HTTPS destination through Bitdefender's `serviceBoards` API. This extends the first-hop test above; it does not show protected internal data.
