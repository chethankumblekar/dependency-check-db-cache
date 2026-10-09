"""Version tags for a Checkstead release.

A tag v1.2.3 publishes the GitHub Action and the Azure DevOps extension.
The floating tags v1 and v1.2 move to that commit. The full tag does not.
"""

from __future__ import annotations

import re

TAG = re.compile(r"^v([0-9]+)\.([0-9]+)\.([0-9]+)$")
SCANNER_REPOSITORY = "ghcr.io/chethankumblekar/dependency-check-db-cache/checkstead"
NVD_NOTICE = (
    "This product uses data from the NVD API but is not endorsed or certified by the NVD."
)


def parse_tag(tag: str) -> tuple[int, int, int]:
    match = TAG.fullmatch(tag.strip())
    if match is None:
        raise ValueError("The release tag must look like v1.2.3.")
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def version_text(parts: tuple[int, int, int]) -> str:
    return f"{parts[0]}.{parts[1]}.{parts[2]}"


def moving_tags(parts: tuple[int, int, int]) -> tuple[str, str]:
    """Major and minor tags that follow the newest patch of that line."""
    return (f"v{parts[0]}", f"v{parts[0]}.{parts[1]}")


def scanner_image(parts: tuple[int, int, int]) -> str:
    return f"{SCANNER_REPOSITORY}:{version_text(parts)}"


def release_notes(tag: str) -> str:
    parts = parse_tag(tag)
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
            "The extension package is attached to this release. "
            "The manifest is public, so other organizations can install it. "
            "The publisher does not need an Azure DevOps organization.",
            "",
            "Upload the VSIX at https://marketplace.visualstudio.com/manage "
            "with New extension, then Azure DevOps. "
            "Microsoft lists it for everyone when the publisher is verified. "
            f"A pipeline then uses `ChecksteadScan@{parts[0]}`.",
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
