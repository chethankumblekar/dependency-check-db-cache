#!/usr/bin/env python3
"""Post one Checkstead comment on a pull request, or update that same comment.

The token is the workflow GITHUB_TOKEN already present in the job. This script
does not read a token from a file, a prompt, or any other variable.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

MARKER = "<!-- checkstead-report -->"


def main() -> int:
    token = os.environ.get("GITHUB_TOKEN", "")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    number = os.environ.get("PR_NUMBER", "")
    path = os.environ.get("COMMENT_FILE", "")
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
    if not token or not repo or not number or not path or not os.path.isfile(path):
        return 0
    with open(path, encoding="utf-8") as handle:
        body = handle.read()
    if MARKER not in body:
        body = MARKER + "\n" + body
    try:
        comment_id = find_comment(api, repo, number, token)
        if comment_id is None:
            send(
                "POST",
                f"{api}/repos/{repo}/issues/{number}/comments",
                token,
                {"body": body},
            )
        else:
            send(
                "PATCH",
                f"{api}/repos/{repo}/issues/comments/{comment_id}",
                token,
                {"body": body},
            )
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        print(
            f"checkstead: pull request comment failed: HTTP {exc.code}. {detail}",
            file=sys.stderr,
        )
        return 1
    return 0


def find_comment(api: str, repo: str, number: str, token: str) -> int | None:
    page = 1
    while True:
        url = f"{api}/repos/{repo}/issues/{number}/comments?per_page=100&page={page}"
        comments = send("GET", url, token, None)
        if not isinstance(comments, list) or not comments:
            return None
        for comment in comments:
            if isinstance(comment, dict) and MARKER in str(comment.get("body") or ""):
                found = comment.get("id")
                if isinstance(found, int):
                    return found
        if len(comments) < 100:
            return None
        page += 1


def send(method: str, url: str, token: str, payload: dict | None):
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Authorization", f"Bearer {token}")
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("X-GitHub-Api-Version", "2022-11-28")
    if payload is not None:
        request.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(request) as response:
        raw = response.read()
    if not raw:
        return None
    return json.loads(raw.decode("utf-8"))


if __name__ == "__main__":
    raise SystemExit(main())
