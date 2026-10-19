"""Version tags for a Checkstead release.

A tag v1.2.3 publishes the GitHub Action and the Azure DevOps extension.
The floating tags v1 and v1.2 move to that commit. The full tag does not.
"""

from __future__ import annotations

import re

TAG = re.compile(r"^v([0-9]+)\.([0-9]+)\.([0-9]+)$")
RC_TAG = re.compile(r"^v([0-9]+)\.([0-9]+)\.([0-9]+)-rc\.([0-9]+)$")
SCANNER_REPOSITORY = "ghcr.io/chethankumblekar/dependency-check-db-cache/checkstead"
NVD_NOTICE = (
    "This product uses data from the NVD API but is not endorsed or certified by the NVD."
)


def parse_tag(tag: str) -> tuple[int, int, int]:
    match = TAG.fullmatch(tag.strip())
    if match is None:
        raise ValueError("The release tag must look like v1.2.3.")
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def is_release_candidate(tag: str) -> bool:
    """A candidate tag is v1.2.3-rc.1. It is not a stable release."""
    return RC_TAG.fullmatch(tag.strip()) is not None


def release_image(tag: str) -> str:
    """Image tag for a stable release or a candidate.

    A candidate keeps the git tag, including the ``v`` and ``-rc.N``.
    CI publishes that tag from ``type=ref,event=tag`` and does not also
    publish ``latest`` or the floating minor tag.
    """
    cleaned = tag.strip()
    if is_release_candidate(cleaned):
        return f"{SCANNER_REPOSITORY}:{cleaned}"
    return scanner_image(parse_tag(cleaned))


def version_text(parts: tuple[int, int, int]) -> str:
    return f"{parts[0]}.{parts[1]}.{parts[2]}"


def moving_tags(parts: tuple[int, int, int]) -> tuple[str, str]:
    """Major and minor tags that follow the newest patch of that line."""
    return (f"v{parts[0]}", f"v{parts[0]}.{parts[1]}")


def scanner_image(parts: tuple[int, int, int]) -> str:
    return f"{SCANNER_REPOSITORY}:{version_text(parts)}"


def release_notes(tag: str) -> str:
    cleaned = tag.strip()
    if is_release_candidate(cleaned):
        image = release_image(cleaned)
        return "\n".join(
            [
                f"Checkstead {cleaned}",
                "",
                "This is a release candidate. It is not a production release.",
                "",
                f"The candidate scanner image is `{image}`.",
                "Verify that image by digest after the publish job finishes.",
                "This tag does not move `latest`, and it does not move the major or minor tags.",
                "",
                "The Azure DevOps extension is not packaged from this tag. "
                "Its version is three integers, and a candidate must not replace the Marketplace listing.",
                "",
                NVD_NOTICE,
                "",
            ]
        )
    parts = parse_tag(cleaned)
    major, minor = moving_tags(parts)
    image = scanner_image(parts)
    return "\n".join(
        [
            f"Checkstead {tag}",
            "",
            "The GitHub Action:",
            "",
            "```yaml",
            f"- uses: chethankumblekar/dependency-check-db-cache@{major}",
            "  with:",
            "    scan: .",
            "    project: my-service",
            "```",
            "",
            f"The tags `{major}` and `{minor}` point at this release. "
            f"The scanner image is `{image}`.",
            "",
            "## GitHub Marketplace",
            "",
            "Listing the action is a one-time step on this release. "
            "GitHub does not offer an API for the Marketplace checkbox.",
            "",
            "1. Accept the GitHub Marketplace Developer Agreement. "
            "The account needs two-factor authentication.",
            "2. Open this release and choose Edit.",
            "3. Select Publish this Action to the GitHub Marketplace.",
            "4. Set the primary category to Security.",
            "5. Update the release.",
            "",
            "Later version tags stay on that listing.",
            "",
            "## Azure DevOps Marketplace",
            "",
            "The release pipeline publishes this public extension "
            "to the Azure DevOps Marketplace.",
            "",
            f"An organization installs it there, then a pipeline uses `ChecksteadScan@{parts[0]}`.",
            "",
            "```yaml",
            f"- task: ChecksteadScan@{parts[0]}",
            "  inputs:",
            "    scan: .",
            "    project: my-service",
            "```",
            "",
            f"The task runs `{image}`. It does not take an NVD API key.",
            "",
            NVD_NOTICE,
            "",
        ]
    )
