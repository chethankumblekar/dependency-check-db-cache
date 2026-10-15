"""Sign in with GitHub or a Microsoft Entra work account.

The server redirects to the provider and exchanges the code itself.
The provider credential from that sign-in is not stored. An app registration
has to be configured before either button works.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import urllib.error
import urllib.parse
import urllib.request

from checkstead.errors import ChecksteadError
from checkstead.http import USER_AGENT, build_opener, ensure_allowed
from checkstead.identity import AuthError, Identity, github_api_base, github_web_base

STATE_COOKIE = "checkstead_sso"
_TENANT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,63}$")


def _env(name: str) -> str:
    return os.environ.get(name, "").strip()


def github_enabled() -> bool:
    return bool(_env("CHECKSTEAD_GITHUB_CLIENT_ID") and _env("CHECKSTEAD_GITHUB_CLIENT_SECRET"))


def entra_enabled() -> bool:
    return bool(_env("CHECKSTEAD_ENTRA_CLIENT_ID") and _env("CHECKSTEAD_ENTRA_CLIENT_SECRET"))


def entra_tenant() -> str:
    tenant = _env("CHECKSTEAD_ENTRA_TENANT") or "organizations"
    if not _TENANT.fullmatch(tenant):
        raise AuthError("CHECKSTEAD_ENTRA_TENANT is not a tenant id or domain.")
    return tenant


def sso_status() -> dict:
    return {
        "github": {"enabled": github_enabled(), "start": "/api/sso/github/start"},
        "entra": {
            "enabled": entra_enabled(),
            "start": "/api/sso/entra/start",
            "tenant": _env("CHECKSTEAD_ENTRA_TENANT") or "organizations",
        },
    }


def new_state() -> str:
    return secrets.token_urlsafe(24)


def state_cookie(state: str) -> str:
    parts = [
        f"{STATE_COOKIE}={state}",
        "HttpOnly",
        "SameSite=Lax",
        "Path=/",
        "Max-Age=600",
    ]
    if os.environ.get("CHECKSTEAD_COOKIE_SECURE") == "1":
        parts.append("Secure")
    return "; ".join(parts)


def public_base(host: str) -> str:
    scheme = "https" if os.environ.get("CHECKSTEAD_COOKIE_SECURE") == "1" else "http"
    cleaned = host.split(",")[0].strip()
    if not cleaned or any(char in cleaned for char in "\r\n "):
        raise AuthError("The server could not tell which host to return to.")
    return f"{scheme}://{cleaned}"


def _redirect(kind: str, base: str) -> str:
    return f"{base}/api/sso/{kind}/callback"


def authorize_url(kind: str, base: str, state: str) -> str:
    redirect_uri = _redirect(kind, base)
    if kind == "github":
        if not github_enabled():
            raise AuthError("GitHub sign-in is not configured on this server.")
        root = github_web_base()
        query = urllib.parse.urlencode(
            {
                "client_id": _env("CHECKSTEAD_GITHUB_CLIENT_ID"),
                "redirect_uri": redirect_uri,
                "scope": "read:user user:email",
                "state": state,
            }
        )
        return f"{root.rstrip('/')}/login/oauth/authorize?{query}"
    if kind == "entra":
        if not entra_enabled():
            raise AuthError("Microsoft Entra sign-in is not configured on this server.")
        tenant = entra_tenant()
        root = _env("CHECKSTEAD_ENTRA_AUTHORIZE") or (
            f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize"
        )
        query = urllib.parse.urlencode(
            {
                "client_id": _env("CHECKSTEAD_ENTRA_CLIENT_ID"),
                "response_type": "code",
                "redirect_uri": redirect_uri,
                "response_mode": "query",
                "scope": "openid profile email",
                "state": state,
            }
        )
        separator = "&" if "?" in root else "?"
        return f"{root}{separator}{query}"
    raise AuthError("That sign-in is not connected yet.")


def _request(url: str, headers: dict[str, str], data: bytes | None = None) -> tuple[int, bytes]:
    ensure_allowed(url)
    request = urllib.request.Request(
        url,
        data=data,
        headers={**headers, "User-Agent": USER_AGENT},
        method="POST" if data is not None else "GET",
    )
    try:
        with build_opener().open(request, timeout=20) as response:
            ensure_allowed(response.geturl())
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except ChecksteadError:
        raise
    except Exception as exc:
        raise AuthError("The identity provider could not be reached.") from exc


def _json_body(status: int, body: bytes, failure: str) -> dict:
    if status >= 400:
        raise AuthError(failure)
    try:
        payload = json.loads(body.decode("utf-8")) if body else {}
    except json.JSONDecodeError as exc:
        raise AuthError(failure) from exc
    if not isinstance(payload, dict):
        raise AuthError(failure)
    return payload


def _form(fields: dict[str, str]) -> bytes:
    return urllib.parse.urlencode(fields).encode("utf-8")


def _github_org(login: str, access_token: str) -> None:
    org = _env("CHECKSTEAD_GITHUB_ORG")
    if not org:
        return
    if not _TENANT.fullmatch(org):
        raise AuthError("CHECKSTEAD_GITHUB_ORG is not an organization login.")
    status, _body = _request(
        f"{github_api_base()}/orgs/{urllib.parse.quote(org)}/members/{urllib.parse.quote(login)}",
        {"Authorization": f"Bearer {access_token}", "Accept": "application/vnd.github+json"},
    )
    if status == 204:
        return
    raise AuthError(f"This GitHub account is not a member of {org}.")


def exchange(kind: str, code: str, base: str) -> Identity:
    if not code or any(char in code for char in "\r\n\x00 "):
        raise AuthError("The identity provider did not return a sign-in code.")
    redirect_uri = _redirect(kind, base)
    if kind == "github":
        if not github_enabled():
            raise AuthError("GitHub sign-in is not configured on this server.")
        root = github_web_base()
        status, body = _request(
            f"{root.rstrip('/')}/login/oauth/access_token",
            {"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"},
            _form(
                {
                    "client_id": _env("CHECKSTEAD_GITHUB_CLIENT_ID"),
                    "client_secret": _env("CHECKSTEAD_GITHUB_CLIENT_SECRET"),
                    "code": code,
                    "redirect_uri": redirect_uri,
                }
            ),
        )
        payload = _json_body(status, body, "GitHub rejected this sign-in.")
        access_token = payload.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise AuthError("GitHub rejected this sign-in.")
        status, body = _request(
            f"{github_api_base()}/user",
            {"Authorization": f"Bearer {access_token}", "Accept": "application/vnd.github+json"},
        )
        user = _json_body(status, body, "GitHub did not identify this sign-in.")
        login = user.get("login")
        subject = user.get("id")
        if not isinstance(login, str) or subject in (None, ""):
            raise AuthError("GitHub did not identify this sign-in.")
        _github_org(login, access_token)
        name = user.get("name")
        display = name.strip() if isinstance(name, str) and name.strip() else login
        return Identity("github", str(subject), login.strip(), display[:200])
    if kind == "entra":
        if not entra_enabled():
            raise AuthError("Microsoft Entra sign-in is not configured on this server.")
        tenant = entra_tenant()
        token_url = _env("CHECKSTEAD_ENTRA_TOKEN") or (
            f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
        )
        status, body = _request(
            token_url,
            {"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"},
            _form(
                {
                    "client_id": _env("CHECKSTEAD_ENTRA_CLIENT_ID"),
                    "client_secret": _env("CHECKSTEAD_ENTRA_CLIENT_SECRET"),
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "scope": "openid profile email",
                }
            ),
        )
        payload = _json_body(status, body, "Microsoft Entra rejected this sign-in.")
        access_token = payload.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise AuthError("Microsoft Entra rejected this sign-in.")
        userinfo = _env("CHECKSTEAD_ENTRA_USERINFO") or "https://graph.microsoft.com/oidc/userinfo"
        status, body = _request(
            userinfo,
            {"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
        )
        user = _json_body(status, body, "Microsoft Entra did not identify this sign-in.")
        login = user.get("preferred_username") or user.get("email")
        subject = user.get("oid") or user.get("sub")
        if not isinstance(login, str) or not login.strip() or subject in (None, ""):
            raise AuthError("Microsoft Entra did not identify this sign-in.")
        name = user.get("name")
        display = name.strip() if isinstance(name, str) and name.strip() else login.strip()
        return Identity("entra", str(subject), login.strip(), display[:200])
    raise AuthError("That sign-in is not connected yet.")
