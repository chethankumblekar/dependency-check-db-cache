#!/usr/bin/env python3
"""Check a running server's GitHub and Entra sign-in setup up to the provider's login page.

Run it against a test deployment after setting the OAuth variables:

  python3 scripts/idp-preflight.py --base https://checkstead-test.example

For each enabled provider it checks that the start endpoint redirects to the
expected provider host with this server's client id, the exact callback URL
derived from CHECKSTEAD_PUBLIC_BASE, the minimal scope, and a state value
that matches an HttpOnly, SameSite state cookie (Secure over https); that a
callback with a wrong state is refused; and that the provider's authorize
page answers. It cannot sign in: that needs a person and a test account. The
manual steps that follow are in docs/operations/identity-provider-testing.md.

Exit 0 when every enabled provider passes, 1 when a check fails, 2 when no
provider is enabled.
"""

from __future__ import annotations

import argparse
import http.client
import json
import ssl
import sys
from urllib.parse import parse_qs, urlsplit

EXPECTED = {
    "github": {"scope": "read:user user:email"},
    "entra": {"scope": "openid profile email"},
}


def _context() -> ssl.SSLContext:
    try:
        import certifi
    except ImportError:
        return ssl.create_default_context()
    return ssl.create_default_context(cafile=certifi.where())


def _request(url: str, headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], list[str], bytes]:
    parts = urlsplit(url)
    if parts.scheme == "https":
        connection = http.client.HTTPSConnection(parts.hostname, parts.port or 443, timeout=20, context=_context())
    else:
        connection = http.client.HTTPConnection(parts.hostname, parts.port or 80, timeout=20)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    try:
        connection.request("GET", path, headers=headers or {})
        response = connection.getresponse()
        body = response.read()
        cookies = response.headers.get_all("Set-Cookie") or []
        return response.status, {key.lower(): value for key, value in response.getheaders()}, cookies, body
    finally:
        connection.close()


def check_provider(base: str, kind: str, provider_host: str | None) -> list[str]:
    problems: list[str] = []
    status, headers, cookies, _body = _request(f"{base}/api/sso/{kind}/start")
    if status != 302:
        return [f"{kind}: start returned HTTP {status}, expected 302"]
    location = headers.get("location", "")
    target = urlsplit(location)
    query = {key: values[0] for key, values in parse_qs(target.query).items()}
    if target.scheme != "https":
        problems.append(f"{kind}: authorize URL is not https: {location}")
    if provider_host and target.hostname != provider_host:
        problems.append(f"{kind}: authorize host is {target.hostname}, expected {provider_host}")
    expected_callback = f"{base}/api/sso/{kind}/callback"
    if query.get("redirect_uri") != expected_callback:
        problems.append(f"{kind}: redirect_uri is {query.get('redirect_uri')!r}, expected {expected_callback!r}")
    if not query.get("client_id"):
        problems.append(f"{kind}: no client_id in the authorize URL")
    if query.get("scope") != EXPECTED[kind]["scope"]:
        problems.append(f"{kind}: scope is {query.get('scope')!r}, expected {EXPECTED[kind]['scope']!r}")
    state = query.get("state", "")
    cookie = next((item for item in cookies if item.startswith("checkstead_sso=")), "")
    if len(state) < 20 or f"checkstead_sso={state}" not in cookie:
        problems.append(f"{kind}: state is missing, short, or not the state cookie")
    flags = cookie.lower()
    if "httponly" not in flags or "samesite=lax" not in flags:
        problems.append(f"{kind}: state cookie is not HttpOnly and SameSite=Lax")
    if base.startswith("https://") and "secure" not in flags:
        problems.append(f"{kind}: state cookie is not Secure on an https origin; set CHECKSTEAD_COOKIE_SECURE=1")
    status, _headers, _cookies, _body = _request(
        f"{base}/api/sso/{kind}/callback?code=preflight&state=wrong",
        {"Cookie": f"checkstead_sso={state}"},
    )
    if status != 400:
        problems.append(f"{kind}: a callback with the wrong state returned HTTP {status}, expected 400")
    page_status, _headers, _cookies, _body = _request(location)
    if page_status >= 500 or page_status == 404:
        problems.append(f"{kind}: the provider's authorize page returned HTTP {page_status}")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base", required=True, help="The origin users open, the same as CHECKSTEAD_PUBLIC_BASE.")
    parser.add_argument("--github-host", default="github.com")
    parser.add_argument("--entra-host", default="login.microsoftonline.com")
    args = parser.parse_args()
    base = args.base.rstrip("/")
    status, _headers, _cookies, body = _request(f"{base}/api/sso")
    if status != 200:
        print(f"GET /api/sso returned HTTP {status}", file=sys.stderr)
        return 1
    enabled = [kind for kind, value in json.loads(body).items() if isinstance(value, dict) and value.get("enabled") and kind in EXPECTED]
    if not enabled:
        print("No identity provider is enabled on this server.", file=sys.stderr)
        return 2
    hosts = {"github": args.github_host, "entra": args.entra_host}
    failures = 0
    for kind in enabled:
        problems = check_provider(base, kind, hosts[kind])
        if problems:
            failures += 1
            for problem in problems:
                print(f"FAIL {problem}")
        else:
            print(f"PASS {kind}: redirect, callback URL, scope, state cookie, wrong-state refusal, provider page")
    print("Automated checks stop at the provider's login page. Finish with docs/operations/identity-provider-testing.md.")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
