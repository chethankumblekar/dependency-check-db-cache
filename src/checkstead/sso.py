"""Sign in with GitHub or a Microsoft Entra work account.

The server redirects to the provider and exchanges the code itself.
The provider credential from that sign-in is not stored. An app registration
has to be configured before either button works.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request

from checkstead.errors import ChecksteadError
from checkstead.github_app import localhost_client
from checkstead.http import USER_AGENT, build_opener, ensure_allowed
from checkstead import avatars
from checkstead.identity import AuthError, Identity, github_api_base, github_avatar, github_web_base

STATE_COOKIE = "checkstead_sso"
# User.Read lets the server read the profile photo once, at sign-in.
ENTRA_SCOPE = "openid profile email User.Read"
_TENANT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,63}$")
_GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_MULTI_TENANT = frozenset({"organizations", "common"})
_ORIGIN_HOST = re.compile(
    r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*"
    r"|\d{1,3}(?:\.\d{1,3}){3}"
    r"|\[[A-Fa-f0-9:]+\])"
    r"(?::[0-9]{1,5})?$"
)


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


def entra_allowed_tenants() -> frozenset[str]:
    """Directory (tenant) ids that may sign in.

    A tenant id in CHECKSTEAD_ENTRA_TENANT is the only one allowed. With
    ``organizations`` or ``common``, CHECKSTEAD_ENTRA_ALLOWED_TENANTS lists
    them. Both empty means any Entra directory, which the server warns about.
    """
    configured = entra_tenant()
    if _GUID.fullmatch(configured):
        return frozenset({configured.lower()})
    allowed = set()
    for item in _env("CHECKSTEAD_ENTRA_ALLOWED_TENANTS").split(","):
        item = item.strip().lower()
        if not item:
            continue
        if not _GUID.fullmatch(item):
            raise AuthError("CHECKSTEAD_ENTRA_ALLOWED_TENANTS must list directory (tenant) ids.")
        allowed.add(item)
    return frozenset(allowed)


def entra_tenant_warning() -> str | None:
    if not entra_enabled():
        return None
    if entra_tenant().lower() in _MULTI_TENANT and not entra_allowed_tenants():
        return (
            "checkstead: Microsoft Entra sign-in accepts any directory. An administrator "
            "still has to add each login, but set CHECKSTEAD_ENTRA_TENANT or "
            "CHECKSTEAD_ENTRA_ALLOWED_TENANTS to your directory id."
        )
    return None


def _id_token_claims(token: object) -> dict:
    """Claims of the ID token from the token endpoint.

    The token came straight from the Entra token endpoint over TLS in exchange
    for this server's client secret, so OpenID Connect Core 3.1.3.7 lets the
    client skip the JWS signature. The claims are still checked.
    """
    if not isinstance(token, str) or token.count(".") != 2:
        raise AuthError("Microsoft Entra did not return an ID token.")
    segment = token.split(".")[1]
    try:
        raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
        claims = json.loads(raw.decode("utf-8"))
    except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
        raise AuthError("Microsoft Entra returned an ID token that is not readable.") from exc
    if not isinstance(claims, dict):
        raise AuthError("Microsoft Entra returned an ID token that is not readable.")
    return claims


def _check_entra_claims(claims: dict) -> str:
    """Audience and directory checks. Returns the directory id."""
    audience = claims.get("aud")
    client_id = _env("CHECKSTEAD_ENTRA_CLIENT_ID")
    if audience != client_id and not (isinstance(audience, list) and client_id in audience):
        raise AuthError("Microsoft Entra issued this sign-in for another application.")
    tenant = claims.get("tid")
    if not isinstance(tenant, str) or not _GUID.fullmatch(tenant):
        raise AuthError("Microsoft Entra did not name the directory for this sign-in.")
    allowed = entra_allowed_tenants()
    if allowed and tenant.lower() not in allowed:
        raise AuthError("This Microsoft Entra directory is not allowed on this server.")
    return tenant.lower()


def sso_status() -> dict:
    return {
        "github": {"enabled": github_enabled(), "start": "/api/sso/github/start"},
        "entra": {
            "enabled": entra_enabled(),
            "start": "/api/sso/entra/start",
            "tenant": _env("CHECKSTEAD_ENTRA_TENANT") or "organizations",
        },
    }


def warn_entra_tenant() -> None:
    message = entra_tenant_warning()
    if message:
        print(message, file=sys.stderr)


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


def configured_public_base() -> str | None:
    """Origin from CHECKSTEAD_PUBLIC_BASE, or None when the operator left it unset."""
    raw = os.environ.get("CHECKSTEAD_PUBLIC_BASE", "").strip()
    if not raw:
        return None
    parsed = urllib.parse.urlsplit(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise AuthError("CHECKSTEAD_PUBLIC_BASE must be an http or https origin.")
    if (
        parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise AuthError(
            "CHECKSTEAD_PUBLIC_BASE must be an origin, without a path, userinfo, or query."
        )
    return f"{parsed.scheme}://{parsed.netloc}"


def public_base(host: str, peer: str | None = None) -> str:
    """Origin for OAuth and the GitHub App manifest.

    A configured CHECKSTEAD_PUBLIC_BASE wins, and the Host header is ignored.
    Without it, only a loopback TCP peer may supply Host. A remote peer has
    to have the origin set explicitly. Host is never proof of localhost.
    """
    configured = configured_public_base()
    if configured:
        return configured
    if peer is not None and not localhost_client(peer):
        raise AuthError(
            "Set CHECKSTEAD_PUBLIC_BASE to the origin clients use. "
            "A Host header from a remote connection is not that origin."
        )
    scheme = "https" if os.environ.get("CHECKSTEAD_COOKIE_SECURE") == "1" else "http"
    cleaned = host.split(",")[0].strip()
    if not cleaned or any(char in cleaned for char in "\r\n\x00 ") or not _ORIGIN_HOST.fullmatch(cleaned):
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
                "scope": ENTRA_SCOPE,
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


def entra_photo_url() -> str | None:
    """Graph photo endpoint, or None.

    An operator who points CHECKSTEAD_ENTRA_USERINFO at another Graph (a
    national cloud) sets CHECKSTEAD_ENTRA_PHOTO too; otherwise no photo is
    fetched rather than sending that token to the public Graph.
    """
    configured = _env("CHECKSTEAD_ENTRA_PHOTO")
    if configured:
        return configured
    if _env("CHECKSTEAD_ENTRA_USERINFO"):
        return None
    return f"https://graph.microsoft.com/v1.0/me/photos/{avatars.SIZE}x{avatars.SIZE}/$value"


def _entra_photo(access_token: str) -> avatars.Avatar | None:
    url = entra_photo_url()
    if url is None:
        return None
    # 404 when the account has no photo; that is not an error.
    return avatars.fetch(url, {"Authorization": f"Bearer {access_token}"})


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
        return Identity("github", str(subject), login.strip(), display[:200], github_avatar(user))
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
                    "scope": ENTRA_SCOPE,
                }
            ),
        )
        payload = _json_body(status, body, "Microsoft Entra rejected this sign-in.")
        access_token = payload.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise AuthError("Microsoft Entra rejected this sign-in.")
        claims = _id_token_claims(payload.get("id_token"))
        _check_entra_claims(claims)
        userinfo = _env("CHECKSTEAD_ENTRA_USERINFO") or "https://graph.microsoft.com/oidc/userinfo"
        status, body = _request(
            userinfo,
            {"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
        )
        user = _json_body(status, body, "Microsoft Entra did not identify this sign-in.")
        login = user.get("preferred_username") or user.get("email") or claims.get("preferred_username")
        subject = user.get("oid") or user.get("sub")
        if not isinstance(login, str) or not login.strip() or subject in (None, ""):
            raise AuthError("Microsoft Entra did not identify this sign-in.")
        # userinfo and the ID token describe the same person for the same app.
        token_sub = claims.get("sub")
        if user.get("sub") and token_sub and user.get("sub") != token_sub:
            raise AuthError("Microsoft Entra returned two different people for one sign-in.")
        name = user.get("name")
        display = name.strip() if isinstance(name, str) and name.strip() else login.strip()
        return Identity(
            "entra", str(subject), login.strip(), display[:200], _entra_photo(access_token)
        )
    raise AuthError("That sign-in is not connected yet.")
