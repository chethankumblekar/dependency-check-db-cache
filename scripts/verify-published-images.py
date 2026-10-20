#!/usr/bin/env python3
"""Check published image attestations. This does not push or build.

Exit 0 when the registry index contains in-toto SPDX and SLSA provenance
and `gh attestation verify` accepts the same digest.

Exit 1 when the registry index has no such attestation.

Exit 2 when the registry cannot be read.

Exit 3 when the registry attestation is present and `gh attestation verify`
does not succeed. Exit 3 is not a pass. The image was published with
BuildKit attestations that GitHub's attestation API does not currently serve.
"""

from __future__ import annotations

import json
import ssl
import subprocess
import sys
import urllib.error
import urllib.request


def _context() -> ssl.SSLContext:
    """certifi when installed: python.org builds on macOS ship without a CA bundle."""
    try:
        import certifi
    except ImportError:
        return ssl.create_default_context()
    return ssl.create_default_context(cafile=certifi.where())


def _token(repository: str) -> str:
    url = f"https://ghcr.io/token?service=ghcr.io&scope=repository:{repository}:pull"
    with urllib.request.urlopen(url, timeout=30, context=_context()) as response:
        payload = json.load(response)
    token = payload.get("token") or ""
    if not token:
        raise RuntimeError("registry token was empty")
    return token


def _get(repository: str, token: str, url: str, accept: str) -> dict:
    request = urllib.request.Request(
        url,
        headers={"Authorization": f"Bearer {token}", "Accept": accept},
    )
    with urllib.request.urlopen(request, timeout=60, context=_context()) as response:
        return json.load(response)


def registry_predicates(image: str) -> list[str]:
    """Return in-toto predicate types attached to an index or manifest digest."""
    name, _, digest = image.partition("@")
    if not name.startswith("ghcr.io/") or not digest.startswith("sha256:"):
        raise RuntimeError("expected ghcr.io/<repo>@sha256:<digest>")
    repository = name.removeprefix("ghcr.io/")
    token = _token(repository)
    index = _get(
        repository,
        token,
        f"https://ghcr.io/v2/{repository}/manifests/{digest}",
        "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json",
    )
    predicates: list[str] = []
    manifests = index.get("manifests") or []
    for item in manifests:
        annotations = item.get("annotations") or {}
        if annotations.get("vnd.docker.reference.type") != "attestation-manifest":
            continue
        attestation = _get(
            repository,
            token,
            f"https://ghcr.io/v2/{repository}/manifests/{item['digest']}",
            "application/vnd.oci.image.manifest.v1+json",
        )
        for layer in attestation.get("layers") or []:
            kind = (layer.get("annotations") or {}).get("in-toto.io/predicate-type")
            if kind:
                predicates.append(kind)
    return predicates


def github_verify(image: str) -> int:
    completed = subprocess.run(
        [
            "gh",
            "attestation",
            "verify",
            f"oci://{image}",
            "--repo",
            "chethankumblekar/dependency-check-db-cache",
        ],
        check=False,
    )
    return completed.returncode


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: verify-published-images.py ghcr.io/owner/image@sha256:...", file=sys.stderr)
        return 2
    worst = 0
    for image in argv[1:]:
        print(f"image: {image}")
        try:
            predicates = registry_predicates(image)
        except (urllib.error.URLError, RuntimeError, KeyError, json.JSONDecodeError) as exc:
            print(f"registry: unreadable ({exc})", file=sys.stderr)
            return 2
        print("registry-predicates: " + (", ".join(predicates) if predicates else "none"))
        required = {
            "https://spdx.dev/Document",
            "https://slsa.dev/provenance/v1",
        }
        if not required.issubset(set(predicates)):
            print("registry: missing SPDX or SLSA provenance", file=sys.stderr)
            return 1
        status = github_verify(image)
        print(f"gh-attestation-verify: {status}")
        if status != 0:
            worst = 3
    return worst


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
