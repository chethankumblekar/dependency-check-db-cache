#!/usr/bin/env python3
"""Keep one Checkstead thread, and a status, on an Azure Repos pull request.

    checkstead-ado-comment                    post or update the thread
    checkstead-ado-comment --status <state>   also post a pull request status
    checkstead-ado-comment --find             find the active pull request for
                                              the pushed branch (no branch policy)

The token is the pipeline's System.AccessToken, mapped into the step as
SYSTEM_ACCESSTOKEN. This script does not read a token from a file, a prompt, or
any other variable. The other values are predefined Azure Pipelines variables.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from urllib.parse import quote, urlparse

MARKER = "<!-- checkstead-report -->"
API_VERSION = "7.1"
# A thread left active can block completion under a "check for comment
# resolution" branch policy. The report informs; the score policy gates.
THREAD_CLOSED = 4
# Anyone who can comment can type the marker, and the build identity cannot
# edit someone else's comment. The thread this script creates also carries this
# property, which the web UI cannot set, and only such a thread is updated.
PROPERTY = "Checkstead.Report"
STATUS_CONTEXT = {"genre": "checkstead", "name": "score-policy"}
_GUID = re.compile(r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
_NUMBER = re.compile(r"^[1-9][0-9]{0,9}$")
# git refuses control characters, space, ~ ^ : ? * [ and backslash in a ref, so a
# ref that passes cannot open an Azure Pipelines logging command ("##vso[").
_BRANCH_REF = re.compile(r"^refs/heads/[^\x00-\x20~^:?*\[\\\x7f]+$")
_LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1"})
_JOB_STATES = {
    "succeeded": "succeeded",
    "succeededwithissues": "succeeded",
    "failed": "failed",
    "canceled": "failed",
}


def main(argv: list[str]) -> int:
    if argv[:1] == ["--find"]:
        return find_main()
    status = None
    if argv[:1] == ["--status"]:
        if len(argv) != 2:
            print("checkstead: --status needs the job status, for example $AGENT_JOBSTATUS.", file=sys.stderr)
            return 2
        status = _JOB_STATES.get(argv[1].strip().lower(), "error")
    elif argv:
        print(f"checkstead: unknown arguments: {' '.join(argv)}", file=sys.stderr)
        return 2
    return comment_main(status)


def comment_main(status: str | None) -> int:
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
        base = pull_request_url(collection, project, repository, number)
        build_link = _build_link(collection, project)
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
                f"{base}/threads?api-version={API_VERSION}",
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
                f"{base}/threads/{thread_id}/comments/{comment_id}?api-version={API_VERSION}",
                token,
                {"content": body},
            )
        if status is not None:
            payload = {
                "state": status,
                "description": {
                    "succeeded": "Checkstead: no introduced finding failed the score policy",
                    "failed": "Checkstead: the score policy failed, or the scan did not finish",
                }.get(status, "Checkstead: the job status was not recognised"),
                "context": STATUS_CONTEXT,
            }
            if build_link:
                payload["targetUrl"] = build_link
            send("POST", f"{base}/statuses?api-version={API_VERSION}", token, payload)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        print(
            f"checkstead: pull request comment failed: HTTP {exc.code}. {detail}",
            file=sys.stderr,
        )
        return 1
    return 0


def find_main() -> int:
    """Print the logging commands that set CHECKSTEAD_PR_ID and CHECKSTEAD_PR_TARGET.

    Under a Build validation policy the pull request is already known. On a CI
    push it is the active pull request whose source is the pushed branch. With
    none, both variables are set empty and the pipeline scans the branch alone.
    """
    known = os.environ.get("SYSTEM_PULLREQUEST_PULLREQUESTID", "")
    if known:
        target = os.environ.get("SYSTEM_PULLREQUEST_TARGETBRANCH", "")
        if not _NUMBER.fullmatch(known) or not _BRANCH_REF.fullmatch(target):
            print("checkstead: the pull request variables are not a pull request.", file=sys.stderr)
            return 1
        return _emit(known, target, "this pull request build")
    token = os.environ.get("SYSTEM_ACCESSTOKEN", "")
    collection = os.environ.get("SYSTEM_COLLECTIONURI", "")
    project = os.environ.get("SYSTEM_TEAMPROJECTID", "")
    repository = os.environ.get("BUILD_REPOSITORY_ID", "")
    source = os.environ.get("BUILD_SOURCEBRANCH", "")
    if not token:
        print("checkstead: SYSTEM_ACCESSTOKEN is not mapped into this step, so no pull request is looked up.")
        return _emit("", "", None)
    if not _BRANCH_REF.fullmatch(source):
        print("checkstead: this build is not for a branch, so it has no pull request.")
        return _emit("", "", None)
    try:
        root = repository_url(collection, project, repository)
    except ValueError as exc:
        print(f"checkstead: pull request lookup skipped: {exc}", file=sys.stderr)
        return 1
    url = (
        f"{root}/pullrequests?searchCriteria.sourceRefName={quote(source, safe='')}"
        f"&searchCriteria.status=active&api-version={API_VERSION}"
    )
    try:
        payload = send("GET", url, token, None)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        print(f"checkstead: pull request lookup failed: HTTP {exc.code}. {detail}", file=sys.stderr)
        return 1
    candidates = [
        item
        for item in (payload.get("value") if isinstance(payload, dict) else None) or []
        if isinstance(item, dict)
        and item.get("sourceRefName") == source
        and item.get("status") == "active"
        and isinstance(item.get("pullRequestId"), int)
        and _BRANCH_REF.fullmatch(str(item.get("targetRefName") or ""))
    ]
    if not candidates:
        print(f"checkstead: no active pull request from {source}. The branch is scanned alone.")
        return _emit("", "", None)
    chosen = max(candidates, key=lambda item: item["pullRequestId"])
    if len(candidates) > 1:
        others = ", ".join(f"#{item['pullRequestId']}" for item in candidates if item is not chosen)
        print(f"checkstead: {source} has more than one active pull request. Using the newest; not {others}.")
    return _emit(str(chosen["pullRequestId"]), chosen["targetRefName"], source)


def _emit(number: str, target: str, source: str | None) -> int:
    if number:
        print(f"checkstead: pull request #{number} from {source} into {target}.")
    print(f"##vso[task.setvariable variable=CHECKSTEAD_PR_ID]{number}")
    print(f"##vso[task.setvariable variable=CHECKSTEAD_PR_TARGET]{target}")
    return 0


def repository_url(collection: str, project: str, repository: str) -> str:
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
    return f"{collection.rstrip('/')}/{project}/_apis/git/repositories/{repository}"


def pull_request_url(collection: str, project: str, repository: str, number: str) -> str:
    root = repository_url(collection, project, repository)
    if not _NUMBER.fullmatch(number):
        raise ValueError("SYSTEM_PULLREQUEST_PULLREQUESTID is not a pull request number.")
    return f"{root}/pullRequests/{number}"


def _build_link(collection: str, project: str) -> str | None:
    build = os.environ.get("BUILD_BUILDID", "")
    if not _NUMBER.fullmatch(build):
        return None
    return f"{collection.rstrip('/')}/{project}/_build/results?buildId={build}"


def find_thread(base: str, token: str) -> tuple[int, int] | None:
    payload = send("GET", f"{base}/threads?api-version={API_VERSION}", token, None)
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
    raise SystemExit(main(sys.argv[1:]))
