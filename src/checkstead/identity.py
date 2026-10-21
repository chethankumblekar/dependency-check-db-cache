"""Who a Git provider token belongs to.

GitHub and Azure DevOps are the providers a server can ask today.
Another host, such as GitLab, is a new provider in this module.
The token is sent once to that host and is not kept.
"""

from __future__ import annotations

import base64
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Callable

from checkstead import avatars
from checkstead.avatars import Avatar
from checkstead.errors import ChecksteadError
from checkstead.http import USER_AGENT, build_opener, ensure_allowed

_LOGIN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}(@[A-Za-z0-9][A-Za-z0-9.-]{0,253})?$"
)
_ORG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,62}$")


class AuthError(ChecksteadError):
    """The token did not identify a person the server can accept."""

    def __init__(self, message: str) -> None:
        super().__init__(message, exit_code=1)


@dataclass(frozen=True)
class Identity:
    provider: str
    subject: str
    login: str
    display_name: str
    # Fetched at sign-in and stored by the server; None when the provider has
    # none or it could not be read.
    avatar: Avatar | None = field(default=None, compare=False, repr=False)


Fetch = Callable[[str, dict[str, str]], dict]


def normalize_login(login: str) -> str:
    cleaned = login.strip()
    if not _LOGIN.fullmatch(cleaned):
        raise AuthError("Login must be letters, numbers, dots, hyphens, or underscores.")
    return cleaned


def _secret(token: str) -> str:
    cleaned = token.strip()
    if not cleaned or any(char in cleaned for char in "\r\n\x00 "):
        raise AuthError("Token is required.")
    return cleaned


def github_api_base() -> str:
    return os.environ.get("CHECKSTEAD_GITHUB_API", "https://api.github.com").rstrip("/")


def github_web_base() -> str:
    """Website for the API in CHECKSTEAD_GITHUB_API.

    https://api.github.com is https://github.com. A GitHub Enterprise Server
    API such as https://host/api/v3 is https://host. CHECKSTEAD_GITHUB_OAUTH
    replaces that website when the API host is not the website.
    """
    override = os.environ.get("CHECKSTEAD_GITHUB_OAUTH", "").strip()
    if override:
        return override.rstrip("/")
    api = github_api_base()
    parsed = urllib.parse.urlparse(api)
    host = (parsed.hostname or "").lower()
    if host == "api.github.com":
        return "https://github.com"
    path = parsed.path.rstrip("/")
    for suffix in ("/api/v3", "/api"):
        if path == suffix or path.endswith(suffix):
            path = path[: -len(suffix)]
            break
    return f"{parsed.scheme}://{parsed.netloc}{path}".rstrip("/")


def azure_api_base() -> str:
    return os.environ.get("CHECKSTEAD_AZURE_DEVOPS_API", "https://dev.azure.com").rstrip("/")


def azure_profile_base(org: str) -> str | None:
    """Profile service for an Azure DevOps Services organization.

    Azure DevOps Server (a custom CHECKSTEAD_AZURE_DEVOPS_API) has no
    separate profile host, so it gets no picture.
    """
    if azure_api_base() != "https://dev.azure.com":
        return None
    return f"https://vssps.dev.azure.com/{org}"


def github_avatar(payload: dict) -> Avatar | None:
    url = payload.get("avatar_url")
    if not isinstance(url, str) or not url:
        return None
    # Public image host: the token is not sent.
    return avatars.fetch(avatars.sized(url))


def _azure_avatar(org: str, basic: str, fetch: Fetch) -> Avatar | None:
    base = azure_profile_base(org)
    if base is None:
        return None
    try:
        payload = fetch(
            f"{base}/_apis/profile/profiles/me/avatar?size=medium&api-version=7.1-preview.1",
            {"Authorization": f"Basic {basic}"},
        )
    except Exception:
        return None
    return avatars.from_azure_payload(payload)


def default_fetch(url: str, headers: dict[str, str]) -> dict:
    ensure_allowed(url)
    request = urllib.request.Request(
        url,
        headers={**headers, "User-Agent": USER_AGENT, "Accept": "application/json"},
    )
    try:
        with build_opener().open(request, timeout=20) as response:
            ensure_allowed(response.geturl())
            body = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        raise AuthError("The identity provider rejected this token.") from exc
    except AuthError:
        raise
    except ChecksteadError as exc:
        raise AuthError(str(exc)) from exc
    except Exception as exc:
        raise AuthError("The identity provider could not be reached.") from exc
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise AuthError("The identity provider did not return an account.") from exc
    if not isinstance(payload, dict):
        raise AuthError("The identity provider did not return an account.")
    return payload


def identify_github(token: str, organization: str | None, fetch: Fetch) -> Identity:
    payload = fetch(
        f"{github_api_base()}/user",
        {"Authorization": f"Bearer {_secret(token)}"},
    )
    login = payload.get("login")
    subject = payload.get("id")
    if not isinstance(login, str) or not login.strip() or subject in (None, ""):
        raise AuthError("GitHub did not identify this token.")
    name = payload.get("name")
    display = name.strip() if isinstance(name, str) and name.strip() else login.strip()
    return Identity("github", str(subject), login.strip(), display[:200], github_avatar(payload))


def identify_azure(token: str, organization: str | None, fetch: Fetch) -> Identity:
    if organization is None or not _ORG.fullmatch(organization.strip()):
        raise AuthError("Azure DevOps needs the organization name.")
    org = organization.strip()
    basic = base64.b64encode(f":{_secret(token)}".encode("utf-8")).decode("ascii")
    # connectionData is a preview resource: Azure DevOps answers a plain "7.1"
    # with 400 "The -preview flag must be supplied".
    payload = fetch(
        f"{azure_api_base()}/{org}/_apis/connectionData?api-version=7.1-preview.1",
        {"Authorization": f"Basic {basic}"},
    )
    user = payload.get("authenticatedUser")
    if not isinstance(user, dict):
        raise AuthError("Azure DevOps did not identify this token.")
    subject = user.get("id")
    props = user.get("properties") if isinstance(user.get("properties"), dict) else {}
    account = props.get("Account") if isinstance(props.get("Account"), dict) else {}
    login = account.get("$value")
    if not isinstance(login, str) or not login.strip():
        raw = user.get("providerDisplayName")
        login = raw.split("<", 1)[0].strip() if isinstance(raw, str) else ""
    if not login or subject in (None, ""):
        raise AuthError("Azure DevOps did not identify this token.")
    display = user.get("customDisplayName") or user.get("providerDisplayName") or login
    display_name = display.strip() if isinstance(display, str) and display.strip() else login
    return Identity(
        "azure-devops",
        str(subject),
        login.strip(),
        display_name[:200],
        _azure_avatar(org, basic, fetch),
    )


def identify_entra(token: str, organization: str | None, fetch: Fetch) -> Identity:
    raise AuthError("Microsoft Entra uses Sign in with Microsoft, not a pasted token.")


PROVIDERS: dict[str, dict] = {
    "github": {
        "label": "GitHub",
        "organization": False,
        "sso": False,
        "identify": identify_github,
    },
    "azure-devops": {
        "label": "Azure DevOps",
        "organization": True,
        "sso": False,
        "identify": identify_azure,
    },
    "entra": {
        "label": "Microsoft Entra",
        "organization": False,
        "sso": True,
        "identify": identify_entra,
    },
}


def list_providers() -> dict:
    return {
        "providers": [
            {
                "key": key,
                "label": spec["label"],
                "organization": spec["organization"],
                "sso": spec["sso"],
            }
            for key, spec in PROVIDERS.items()
        ],
        "later": "GitLab and other Git hosts are not connected yet.",
    }


def identify(
    provider: str,
    token: str,
    organization: str | None = None,
    fetch: Fetch | None = None,
) -> Identity:
    spec = PROVIDERS.get(provider)
    if spec is None:
        raise AuthError("That Git host is not connected yet.")
    return spec["identify"](token, organization, fetch or default_fetch)
