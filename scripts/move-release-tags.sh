#!/usr/bin/env bash
# Point the major and minor tags at the full version tag that is checked out.
# The full tag v1.2.3 stays where it was pushed. Only v1 and v1.2 move.
set -euo pipefail

tag=${1:?usage: move-release-tags.sh vMAJOR.MINOR.PATCH}
if [[ "$tag" == *-rc.* ]]; then
  echo "A release candidate does not move floating tags." >&2
  exit 1
fi
root=$(cd "$(dirname "$0")/.." && pwd)

head=$(git rev-parse HEAD)
tagged=$(git rev-parse "${tag}^{commit}")
if [[ "$head" != "$tagged" ]]; then
  echo "HEAD is not ${tag}." >&2
  exit 1
fi

mapfile -t names < <(PYTHONPATH="${root}/src" python3 - "$tag" <<'PY'
import sys
from checkstead.release import moving_tags, parse_tag

for name in moving_tags(parse_tag(sys.argv[1])):
    print(name)
PY
)

for name in "${names[@]}"; do
  git tag -f "$name" -m "Checkstead ${name}"
done

refs=()
for name in "${names[@]}"; do
  refs+=("refs/tags/${name}")
done
git push origin "${refs[@]}" --force
echo "Moved ${names[*]} to ${tag}."
