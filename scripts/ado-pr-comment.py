#!/usr/bin/env python3
"""Post one Checkstead thread on an Azure Repos pull request, or update that thread.

The token is the pipeline's System.AccessToken, mapped into the step as
SYSTEM_ACCESSTOKEN. This script does not read a token from a file, a prompt, or
any other variable. The other values are the predefined variables an Azure
Pipelines pull request build already sets.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from urllib.parse import urlparse

MARKER = "<!-- checkstead-report -->"
API_VERSION = "7.1"
# A thread left active can block completion under a "check for comment
# resolution" branch policy. The report informs; the score policy gates.
THREAD_CLOSED = 4
# Anyone who can comment can type the marker, and the build identity cannot
# edit someone else's comment. The thread this script creates also carries this
# property, which the web UI cannot set, and only such a thread is updated.
PROPERTY = "Checkstead.Report"
_GUID = re.compile(r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
_NUMBER = re.compile(r"^[1-9][0-9]{0,9}$")
_LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1"})


def main() -> int:
    token = os.environ.get("SYSTEM_ACCESSTOKEN", "")
    collection = os.environ.get("SYSTEM_COLLECTIONURI", "")
    project = os.environ.get("SYSTEM_TEAMPROJECTID", "")
    repository = os.environ.get("BUILD_REPOSITORY_ID", "")
    number = os.environ.get("SYSTEM_PULLREQUEST_PULLREQUESTID", "")
    path = os.environ.get("COMMENT_FILE", "")
    if not token or not collection or not project or not repository or not number:
        return 0
    if not path or not os.path.isfile(path):
        return 0
    try:
        base = threads_url(collection, project, repository, number)
    except ValueError as exc:
        print(f"checkstead: pull request comment skipped: {exc}", file=sys.stderr)
        return 1
    with open(path, encoding="utf-8") as handle:
        body = handle.read()
    if MARKER not in body:
        body = MARKER + "\n" + body
    try:
        found = find_thread(base, token)
        if found is None:
            send(
                "POST",
                f"{base}?api-version={API_VERSION}",
                token,
                {
                    "comments": [{"parentCommentId": 0, "content": body, "commentType": 1}],
                    "status": THREAD_CLOSED,
                    "properties": {PROPERTY: {"$type": "System.String", "$value": "1"}},
                },
            )
        else:
            thread_id, comment_id = found
            send(
                "PATCH",
                f"{base}/{thread_id}/comments/{comment_id}?api-version={API_VERSION}",
                token,
                {"content": body},
            )
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        print(
            f"checkstead: pull request comment failed: HTTP {exc.code}. {detail}",
            file=sys.stderr,
        )
        return 1
    return 0


def threads_url(collection: str, project: str, repository: str, number: str) -> str:
    parsed = urlparse(collection)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" and not (parsed.scheme == "http" and host in _LOOPBACK):
        raise ValueError("SYSTEM_COLLECTIONURI must be https.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("SYSTEM_COLLECTIONURI must be a plain collection URL.")
    if not _GUID.fullmatch(project):
        raise ValueError("SYSTEM_TEAMPROJECTID is not a project id.")
    if not _GUID.fullmatch(repository):
        raise ValueError("BUILD_REPOSITORY_ID is not a repository id.")
    if not _NUMBER.fullmatch(number):
        raise ValueError("SYSTEM_PULLREQUEST_PULLREQUESTID is not a pull request number.")
    root = collection.rstrip("/")
    return f"{root}/{project}/_apis/git/repositories/{repository}/pullRequests/{number}/threads"


def find_thread(base: str, token: str) -> tuple[int, int] | None:
    payload = send("GET", f"{base}?api-version={API_VERSION}", token, None)
    threads = payload.get("value") if isinstance(payload, dict) else None
    if not isinstance(threads, list):
        return None
    for thread in threads:
        if not isinstance(thread, dict) or thread.get("isDeleted"):
            continue
        properties = thread.get("properties")
        if not isinstance(properties, dict) or PROPERTY not in properties:
            continue
        comments = thread.get("comments")
        if not isinstance(comments, list) or not comments:
            continue
        # Only the comment that opened the thread is Checkstead's; replies are people's.
        comment = comments[0]
        if not isinstance(comment, dict) or comment.get("isDeleted"):
            continue
        if MARKER not in str(comment.get("content") or ""):
            continue
        thread_id = thread.get("id")
        comment_id = comment.get("id")
        if isinstance(thread_id, int) and isinstance(comment_id, int):
            return thread_id, comment_id
    return None


def send(method: str, url: str, token: str, payload: dict | None):
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Authorization", f"Bearer {token}")
    request.add_header("Accept", "application/json")
    if payload is not None:
        request.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(request) as response:
        raw = response.read()
    if not raw:
        return None
    return json.loads(raw.decode("utf-8"))


if __name__ == "__main__":
    raise SystemExit(main())
