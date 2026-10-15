"""A GitHub App a user or an organization owner installs from the local server.

The API host is CHECKSTEAD_GITHUB_API. github.com is the default.
A GitHub Enterprise Server base such as https://host/api/v3 uses that host.
The private key stays in the data directory and is not written into a page,
a log line, or an error.
"""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, datetime, timezone
from html import escape
from pathlib import Path

from checkstead.config import load_config
from checkstead.errors import ChecksteadError, RefusedHost
from checkstead.http import USER_AGENT, build_opener, download, ensure_allowed
from checkstead.identity import github_api_base, github_web_base
from checkstead.scan import default_cache_dir, run_scan
from checkstead.snapshot import safe_extract

GITHUB_COOKIE = "checkstead_github"
_ORG = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
_REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_SLUG = re.compile(r"^[A-Za-z0-9-]{1,100}$")
_ACCEPT = "application/vnd.github+json"
_API_VERSION = "2022-11-28"


def localhost_client(host: str) -> bool:
    return host in {"127.0.0.1", "::1"}


def normalize_org(organization: str) -> str:
    cleaned = organization.strip()
    if not _ORG.fullmatch(cleaned):
        raise ChecksteadError("Enter a GitHub user login or an organization login.")
    return cleaned


def build_manifest(public_base: str) -> dict:
    base = public_base.rstrip("/")
    return {
        "name": "Checkstead",
        "url": base + "/",
        "redirect_url": base + "/api/github/manifest/callback",
        "setup_url": base + "/api/github/setup",
        "description": "Scan this account's repositories with Checkstead.",
        "public": False,
        "default_permissions": {"contents": "read", "metadata": "read"},
        "default_events": [],
    }


def manifest_target(organization: str, state: str, account_type: str = "Organization") -> str:
    org = normalize_org(organization)
    query = urllib.parse.urlencode({"state": state})
    if account_type == "User":
        return f"{github_web_base()}/settings/apps/new?{query}"
    return f"{github_web_base()}/organizations/{urllib.parse.quote(org)}/settings/apps/new?{query}"


def _app_dir(data_dir: Path) -> Path:
    path = data_dir / "github-app"
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def _write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def _read_json(path: Path) -> dict | None:
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def github_status(data_dir: Path) -> dict:
    directory = data_dir / "github-app"
    app = _read_json(directory / "app.json")
    installation = _read_json(directory / "installation.json")
    key = directory / "private-key.pem"
    app_public = None
    if app and key.is_file() and _SLUG.fullmatch(str(app.get("slug") or "")):
        app_public = {
            "id": app.get("id"),
            "slug": app.get("slug"),
            "organization": app.get("organization"),
            "accountType": app.get("accountType") or "Organization",
        }
    installation_public = None
    if installation and installation.get("accountType") in {"Organization", "User"}:
        installation_public = {
            "id": installation.get("id"),
            "organization": installation.get("organization"),
            "accountType": installation.get("accountType"),
        }
    return {
        "api": github_api_base(),
        "web": github_web_base(),
        "app": app_public,
        "installation": installation_public,
    }


def account_kind(login: str, transport=None) -> str:
    """User or Organization, from the GitHub account record. This does not call the NVD."""
    transport = transport or default_transport
    status, body = github_request(
        "GET",
        f"{github_api_base()}/users/{urllib.parse.quote(login)}",
        {"Accept": _ACCEPT, "X-GitHub-Api-Version": _API_VERSION},
        None,
        transport,
    )
    payload = _json_object(status, body, "GitHub did not identify that login.")
    kind = payload.get("type")
    if kind in {"User", "Organization"}:
        return kind
    raise ChecksteadError("GitHub did not identify that login.")


def begin_manifest(
    data_dir: Path,
    organization: str,
    public_base: str,
    state: str,
    transport=None,
    account_type: str | None = None,
) -> str:
    org = normalize_org(organization)
    if not state or any(char in state for char in "\r\n\x00 "):
        raise ChecksteadError("The GitHub App could not be started.")
    if account_type in {"User", "Organization"}:
        kind = account_type
    else:
        kind = account_kind(org, transport)
    directory = _app_dir(data_dir)
    _write_private(
        directory / "pending.json",
        json.dumps({"state": state, "organization": org, "accountType": kind}),
    )
    manifest = json.dumps(build_manifest(public_base), separators=(",", ":"))
    action = escape(manifest_target(org, state, kind), quote=True)
    hidden = escape(manifest, quote=True)
    org_text = escape(org)
    who = "personal account" if kind == "User" else "organization"
    return (
        "<!DOCTYPE html><html lang=\"en\"><meta charset=\"utf-8\">"
        "<title>Create the Checkstead GitHub App</title>"
        f"<p>Checkstead is opening GitHub so you can approve the app for the {who} {org_text}.</p>"
        f"<form method=\"post\" action=\"{action}\">"
        f"<input type=\"hidden\" name=\"manifest\" value=\"{hidden}\">"
        "<button type=\"submit\">Continue on GitHub</button>"
        "</form><script>document.forms[0].submit()</script></html>"
    )


def _code(value: str) -> str:
    cleaned = value.strip()
    if not cleaned or len(cleaned) > 512 or any(char in cleaned for char in "\r\n\x00 /\\"):
        raise ChecksteadError("GitHub did not return a usable app code.")
    return cleaned


def _json_object(status: int, body: bytes, failure: str) -> dict:
    if status >= 400 or not body:
        raise ChecksteadError(failure)
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ChecksteadError(failure) from exc
    if not isinstance(payload, dict):
        raise ChecksteadError(failure)
    return payload


def github_request(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes | None,
    transport,
) -> tuple[int, bytes]:
    ensure_allowed(url)
    return transport(method, url, headers, body)


def default_transport(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes | None,
) -> tuple[int, bytes]:
    ensure_allowed(url)
    request = urllib.request.Request(
        url,
        data=body,
        headers={**headers, "User-Agent": USER_AGENT},
        method=method,
    )
    try:
        with build_opener().open(request, timeout=60) as response:
            ensure_allowed(response.geturl())
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        location = exc.geturl() if hasattr(exc, "geturl") else url
        ensure_allowed(location or url)
        return exc.code, exc.read()
    except RefusedHost:
        raise
    except ChecksteadError:
        raise
    except Exception as exc:
        raise ChecksteadError("GitHub could not be reached.") from exc


def _api_headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": _ACCEPT,
        "X-GitHub-Api-Version": _API_VERSION,
    }


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def app_jwt(app_id: str, pem_path: Path, now: int | None = None) -> str:
    """RS256 JWT for the GitHub App. openssl signs it. The key is not logged."""
    issued = int(datetime.now(timezone.utc).timestamp()) if now is None else now
    header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64url(
        json.dumps(
            {"iat": issued - 60, "exp": issued + 540, "iss": str(app_id)},
            separators=(",", ":"),
        ).encode()
    )
    signing = f"{header}.{payload}".encode("ascii")
    try:
        signature = subprocess.check_output(
            ["openssl", "dgst", "-sha256", "-sign", str(pem_path)],
            input=signing,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ChecksteadError("openssl could not sign the GitHub App token.") from exc
    return f"{header}.{payload}.{_b64url(signature)}"


def pending_organization(data_dir: Path, state: str) -> str:
    login, _kind = pending_account(data_dir, state)
    return login


def pending_account(data_dir: Path, state: str) -> tuple[str, str]:
    pending = _read_json(data_dir / "github-app" / "pending.json")
    if not pending or pending.get("state") != state:
        raise ChecksteadError("GitHub could not be confirmed. Create the app again.")
    kind = str(pending.get("accountType") or "Organization")
    if kind not in {"User", "Organization"}:
        kind = "Organization"
    return normalize_org(str(pending.get("organization") or "")), kind


def clear_pending(data_dir: Path) -> None:
    (data_dir / "github-app" / "pending.json").unlink(missing_ok=True)


def exchange_manifest(
    data_dir: Path,
    code: str,
    organization: str,
    transport=None,
    account_type: str = "Organization",
) -> dict:
    org = normalize_org(organization)
    kind = account_type if account_type in {"User", "Organization"} else "Organization"
    usable = _code(code)
    transport = transport or default_transport
    quoted = urllib.parse.quote(usable, safe="")
    status, body = github_request(
        "POST",
        f"{github_api_base()}/app-manifests/{quoted}/conversions",
        {"Accept": _ACCEPT, "X-GitHub-Api-Version": _API_VERSION},
        b"",
        transport,
    )
    payload = _json_object(status, body, "GitHub did not create the app.")
    app_id = payload.get("id")
    slug = payload.get("slug")
    pem = payload.get("pem")
    if app_id in (None, "") or not isinstance(slug, str) or not _SLUG.fullmatch(slug):
        raise ChecksteadError("GitHub did not create the app.")
    if not isinstance(pem, str) or "PRIVATE KEY" not in pem:
        raise ChecksteadError("GitHub did not create the app.")
    directory = _app_dir(data_dir)
    _write_private(directory / "private-key.pem", pem if pem.endswith("\n") else pem + "\n")
    _write_private(
        directory / "credentials.json",
        json.dumps(
            {
                "clientId": payload.get("client_id") or "",
                "clientSecret": payload.get("client_secret") or "",
                "webhookSecret": payload.get("webhook_secret") or "",
            }
        ),
    )
    public = {"id": app_id, "slug": slug, "organization": org, "accountType": kind}
    _write_private(directory / "app.json", json.dumps(public))
    return public


def _load_app(data_dir: Path) -> tuple[dict, Path]:
    directory = data_dir / "github-app"
    app = _read_json(directory / "app.json")
    key = directory / "private-key.pem"
    if not app or not key.is_file():
        raise ChecksteadError("Create the GitHub App first.")
    if not _SLUG.fullmatch(str(app.get("slug") or "")):
        raise ChecksteadError("Create the GitHub App first.")
    return app, key


def accept_installation(data_dir: Path, payload: dict) -> dict:
    app, _key = _load_app(data_dir)
    account = payload.get("account")
    if not isinstance(account, dict) or account.get("type") not in {"Organization", "User"}:
        raise ChecksteadError("Checkstead accepts a GitHub App installation on a user or an organization.")
    login = str(account.get("login") or "")
    try:
        org = normalize_org(login)
    except ChecksteadError as exc:
        raise ChecksteadError(
            "Checkstead accepts a GitHub App installation on a user or an organization."
        ) from exc
    expected = str(app.get("organization") or "")
    expected_type = str(app.get("accountType") or "Organization")
    account_type = str(account.get("type"))
    if expected_type not in {"User", "Organization"}:
        expected_type = "Organization"
    if account_type != expected_type:
        created = "organization" if expected_type == "Organization" else "user"
        raise ChecksteadError(
            f"This installation is a {account_type.lower()} account, "
            f"and the app was created for the {created} {expected}."
        )
    if expected.casefold() != org.casefold():
        raise ChecksteadError(f"This installation is for {org}, not {expected}.")
    installation_id = payload.get("id")
    if installation_id in (None, "") or not str(installation_id).isdigit():
        raise ChecksteadError("GitHub did not return an installation.")
    stored = {"id": int(installation_id), "organization": org, "accountType": account_type}
    _write_private(data_dir / "github-app" / "installation.json", json.dumps(stored))
    return {"id": stored["id"], "organization": org}


def complete_setup(data_dir: Path, installation_id: str, transport=None) -> dict:
    if not str(installation_id).isdigit() or len(str(installation_id)) > 20:
        raise ChecksteadError("GitHub did not return an installation.")
    app, key = _load_app(data_dir)
    transport = transport or default_transport
    token = app_jwt(str(app["id"]), key)
    status, body = github_request(
        "GET",
        f"{github_api_base()}/app/installations/{installation_id}",
        _api_headers(token),
        None,
        transport,
    )
    payload = _json_object(status, body, "GitHub did not accept the installation.")
    return accept_installation(data_dir, payload)


def _installation_token(data_dir: Path, transport) -> tuple[dict, str]:
    app, key = _load_app(data_dir)
    installation = _read_json(data_dir / "github-app" / "installation.json")
    if not installation or installation.get("accountType") not in {"Organization", "User"}:
        raise ChecksteadError("Install the GitHub App on the account first.")
    token = app_jwt(str(app["id"]), key)
    status, body = github_request(
        "POST",
        f"{github_api_base()}/app/installations/{installation['id']}/access_tokens",
        {**_api_headers(token), "Content-Type": "application/json"},
        b"{}",
        transport,
    )
    payload = _json_object(status, body, "GitHub did not provide an installation token.")
    access = payload.get("token")
    if not isinstance(access, str) or not access:
        raise ChecksteadError("GitHub did not provide an installation token.")
    return installation, access


def list_repositories(token: str, transport) -> list[str]:
    names: list[tuple[str, str | None]] = []
    for page in range(1, 101):
        status, body = github_request(
            "GET",
            f"{github_api_base()}/installation/repositories?per_page=100&page={page}",
            _api_headers(token),
            None,
            transport,
        )
        payload = _json_object(status, body, "GitHub did not list this account's repositories.")
        batch = payload.get("repositories")
        if not isinstance(batch, list):
            raise ChecksteadError("GitHub did not list this account's repositories.")
        for repo in batch:
            if isinstance(repo, dict) and isinstance(repo.get("full_name"), str):
                names.append((repo["full_name"], _branch_name(repo.get("default_branch"))))
        if len(batch) < 100:
            break
    return names


def _branch_name(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    if not cleaned or len(cleaned) > 200 or any(char in cleaned for char in "\r\n\x00"):
        return None
    return cleaned


def _today() -> date:
    override = os.environ.get("CHECKSTEAD_TODAY", "").strip()
    if override:
        try:
            return date.fromisoformat(override)
        except ValueError as exc:
            raise ChecksteadError("CHECKSTEAD_TODAY must be YYYY-MM-DD.") from exc
    return datetime.now(timezone.utc).date()


def default_fetch_zip(url: str, headers: dict[str, str], dest: Path) -> None:
    download(url, dest, headers=headers)


def _scan_tree(zip_path: Path) -> Path:
    dest = zip_path.parent / "tree"
    safe_extract(zip_path, dest)
    children = [path for path in dest.iterdir() if path.is_dir()]
    if len(children) == 1:
        return children[0]
    return dest


def scan_installed_repositories(
    data_dir: Path,
    scans_dir: Path,
    cwd: Path,
    transport=None,
    scan=None,
    fetch_zip=None,
) -> list[dict]:
    """Download each repository the installation can read and scan it.

    The score policy and the optional private suppression file come from
    checkstead.yml in cwd. A missing suppression file is left unset.
    """
    transport = transport or default_transport
    scan = scan or run_scan
    fetch_zip = fetch_zip or default_fetch_zip
    config = load_config(None, cwd)
    _installation, access = _installation_token(data_dir, transport)
    names = list_repositories(access, transport)
    scans_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    results: list[dict] = []
    for full_name, branch_name in names:
        entry = {
            "repository": full_name,
            "scorePolicy": config.score_policy,
            "threshold": config.threshold,
            "failOnKev": config.fail_on_kev,
            "failUnscored": config.fail_unscored,
            "privateSuppressions": config.private_suppressions,
        }
        if not _REPO.fullmatch(full_name):
            entry["error"] = "GitHub returned a repository name Checkstead will not scan."
            results.append(entry)
            continue
        owner, repo = full_name.split("/", 1)
        url = (
            f"{github_api_base()}/repos/{urllib.parse.quote(owner)}/"
            f"{urllib.parse.quote(repo)}/zipball"
        )
        out_dir = scans_dir / f"{owner}--{repo}--{stamp}"
        entry["report"] = str(out_dir / "checkstead.txt")
        workspace = Path(tempfile.mkdtemp(prefix="checkstead-github-"))
        try:
            archive = workspace / "repo.zip"
            ensure_allowed(url)
            fetch_zip(url, _api_headers(access), archive)
            tree = _scan_tree(archive)
            scan(
                [tree],
                project=full_name,
                config_snapshot_url=config.snapshot_url,
                out_dir=out_dir,
                cache_dir=default_cache_dir(),
                today=_today(),
                dry_run=False,
                score_policy=config.score_policy,
                threshold=config.threshold,
                fail_on_kev=config.fail_on_kev,
                fail_unscored=config.fail_unscored,
                private_suppressions=config.private_suppressions,
                branch=branch_name,
            )
        except ChecksteadError as exc:
            entry["error"] = str(exc)
        finally:
            shutil.rmtree(workspace, ignore_errors=True)
        results.append(entry)
    return results


def install_url(data_dir: Path) -> str:
    app, _key = _load_app(data_dir)
    slug = urllib.parse.quote(str(app["slug"]))
    return f"{github_web_base()}/apps/{slug}/installations/new"


def _shell(title: str, body: str) -> str:
    return (
        "<!DOCTYPE html><html lang=\"en\"><meta charset=\"utf-8\">"
        f"<title>{escape(title)}</title>"
        "<style>body{font:16px/1.45 ui-sans-serif,sans-serif;background:#f6f3ec;"
        "color:#1c1915;margin:0}main{max-width:42rem;margin:0 auto;padding:32px 24px}"
        "a,button{color:inherit}button{font:inherit;padding:8px 12px}"
        "input{font:inherit;padding:8px;width:100%;max-width:24rem}"
        "p,li{max-width:68ch}</style>"
        f"<main><h1>{escape(title)}</h1>{body}</main></html>"
    )


def render_github_page(status: dict) -> str:
    api = escape(str(status.get("api") or ""))
    web = escape(str(status.get("web") or ""))
    parts = [
        f"<p>GitHub API <code>{api}</code>. Website <code>{web}</code>.</p>",
        "<p>Checkstead creates the GitHub App and sends you to GitHub "
        "to approve the install. A user login installs the app on that personal account. "
        "An organization login installs it on that organization. GitHub returns the app id, "
        "private key, and client credentials, and Checkstead stores them. There is no token field.</p>"
        "<p>The app reads repository contents and metadata. "
        "A scan uses the score policy in checkstead.yml in the directory "
        "where the server was started. With no project file, the policy is "
        "prefer-newest. A private suppression file stays optional.</p>",
    ]
    app = status.get("app")
    installation = status.get("installation")
    if not app:
        parts.append(
            "<form method=\"post\" action=\"/api/github/manifest\">"
            "<fieldset><legend>Account</legend>"
            "<label><input type=\"radio\" name=\"account\" value=\"user\" checked> "
            "Personal account</label> "
            "<label><input type=\"radio\" name=\"account\" value=\"organization\"> "
            "Organization</label>"
            "</fieldset>"
            "<p><label>GitHub login<br>"
            "<input name=\"login\" required autocomplete=\"username\"></label></p>"
            "<p>For a personal account, type the user login.</p>"
            "<button type=\"submit\">Create the GitHub App</button></form>"
        )
    else:
        org = escape(str(app.get("organization") or ""))
        slug = escape(str(app.get("slug") or ""))
        parts.append(f"<p>App <code>{slug}</code> is ready for {org}.</p>")
        if not installation:
            link = escape(f"{status.get('web')}/apps/{app.get('slug')}/installations/new", quote=True)
            parts.append(
                f"<p><a href=\"{link}\">Install</a> approves the app on {org}.</p>"
            )
        else:
            installed = escape(str(installation.get("organization") or ""))
            parts.append(f"<p>Installed on {installed}.</p>")
            parts.append(
                "<form method=\"post\" action=\"/api/github/scan\">"
                "<button type=\"submit\">Scan this account's repositories</button>"
                "</form>"
            )
    parts.append("<p><a href=\"/\">Timeline</a></p>")
    return _shell("GitHub", "".join(parts))


def render_message(title: str, paragraphs: list[str], link: str | None = None, label: str = "") -> str:
    body = "".join(f"<p>{escape(text)}</p>" for text in paragraphs)
    if link:
        body += f"<p><a href=\"{escape(link, quote=True)}\">{escape(label or link)}</a></p>"
    body += "<p><a href=\"/github\">GitHub</a></p>"
    return _shell(title, body)


def render_scan_results(scans: list[dict]) -> str:
    if not scans:
        body = "<p>This installation has no repositories.</p>"
    else:
        items = []
        for scan in scans:
            repo = escape(str(scan.get("repository") or ""))
            policy = escape(str(scan.get("scorePolicy") or ""))
            line = f"{repo}: score policy {policy}"
            error = scan.get("error")
            if error:
                line += f". {escape(str(error))}"
            else:
                line += f". Report {escape(str(scan.get('report') or ''))}"
            items.append(f"<li>{line}</li>")
        body = "<ul>" + "".join(items) + "</ul>"
    body += "<p><a href=\"/github\">GitHub</a></p>"
    return _shell("Repository scan", body)
