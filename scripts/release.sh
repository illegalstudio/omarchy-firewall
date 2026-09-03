#!/usr/bin/env bash
# Create and publish a semantic version release.
#
# Usage: scripts/release.sh
#   or:  make release
#
# Reads local and origin refs without fetching, proposes a version, updates
# manifest.json, runs the project checks, creates an annotated tag, and pushes
# the branch and tag atomically. The tag triggers the GitHub release workflow.

set -euo pipefail

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: required command not found: $1" >&2
    exit 1
  fi
}

require_command git
require_command make
require_command node
require_command omarchy
require_command perl
require_command python3

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "error: not inside a git repository" >&2
  exit 1
fi

cd "$(git rev-parse --show-toplevel)"

if [[ ! -f manifest.json ]]; then
  echo "error: manifest.json was not found at the repository root" >&2
  exit 1
fi

if [[ -n "$(git status --porcelain=v1 --untracked-files=all)" ]]; then
  echo "error: working tree is not clean; commit or stash changes first" >&2
  git status --short
  exit 1
fi

branch="$(git symbolic-ref --quiet --short HEAD || true)"
if [[ -z "$branch" ]]; then
  echo "error: releases cannot be created from a detached HEAD" >&2
  exit 1
fi

if ! git remote get-url origin >/dev/null 2>&1; then
  echo "error: git remote 'origin' is not configured" >&2
  exit 1
fi

upstream="$(git rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>/dev/null || true)"
if [[ -z "$upstream" ]]; then
  echo "error: branch '$branch' has no upstream" >&2
  exit 1
fi

if [[ "$upstream" != origin/* ]]; then
  echo "error: branch '$branch' must track a branch on origin" >&2
  exit 1
fi

remote_branch="${upstream#origin/}"
if ! remote_refs="$(git ls-remote --heads --tags --refs origin)"; then
  echo "error: could not read refs from origin" >&2
  exit 1
fi

remote_commit=""
remote_tags=()
while IFS=$'\t' read -r object_id ref_name; do
  [[ -z "${ref_name:-}" ]] && continue
  if [[ "$ref_name" == "refs/heads/${remote_branch}" ]]; then
    remote_commit="$object_id"
  elif [[ "$ref_name" == refs/tags/* ]]; then
    remote_tags+=("${ref_name#refs/tags/}")
  fi
done <<< "$remote_refs"

if [[ -z "$remote_commit" ]]; then
  echo "error: remote branch 'origin/$remote_branch' was not found" >&2
  exit 1
fi

local_commit="$(git rev-parse HEAD)"
if [[ "$local_commit" != "$remote_commit" ]]; then
  echo "error: branch '$branch' must match '$upstream' before releasing" >&2
  echo "  local:  $local_commit" >&2
  echo "  remote: $remote_commit" >&2
  exit 1
fi

manifest_version="$(python3 - <<'PY'
import json
import re
from pathlib import Path

manifest = json.loads(Path("manifest.json").read_text(encoding="utf-8"))
version = manifest.get("version")
if not isinstance(version, str) or not re.fullmatch(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)",
    version,
):
    raise SystemExit("manifest version must use MAJOR.MINOR.PATCH without leading zeros")
print(version)
PY
)"

tag_candidates=()
while IFS= read -r tag_name; do
  tag_candidates+=("$tag_name")
done < <(git tag --list 'v*')
tag_candidates+=("${remote_tags[@]}")

latest="$(python3 - "${tag_candidates[@]}" <<'PY'
import re
import sys

pattern = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
versions = []
for tag in sys.argv[1:]:
    match = pattern.fullmatch(tag)
    if match:
        versions.append((tuple(map(int, match.groups())), tag))
print(max(versions)[1] if versions else "")
PY
)"

if [[ -z "$latest" ]]; then
  proposed="v${manifest_version}"
  echo "No existing semantic version tags found."
else
  proposed="$(python3 - "$latest" <<'PY'
import sys

major, minor, patch = map(int, sys.argv[1][1:].split("."))
print(f"v{major}.{minor}.{patch + 1}")
PY
)"
  echo "Latest semantic version tag: $latest"
fi

echo "Manifest version: $manifest_version"
echo "Proposed release: $proposed"
echo
printf "Version to release [%s]: " "$proposed"
input=""
read -r input || true

version="${input:-$proposed}"
if [[ "$version" != v* ]]; then
  version="v${version}"
fi

if [[ ! "$version" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  echo "error: version must use vMAJOR.MINOR.PATCH without leading zeros (got '$version')" >&2
  exit 1
fi

if [[ -n "$latest" ]] && ! python3 - "$version" "$latest" <<'PY'
import sys

target = tuple(map(int, sys.argv[1][1:].split(".")))
latest = tuple(map(int, sys.argv[2][1:].split(".")))
raise SystemExit(0 if target > latest else 1)
PY
then
  echo "error: version '$version' must be newer than '$latest'" >&2
  exit 1
fi

if git show-ref --verify --quiet "refs/tags/${version}"; then
  echo "error: tag '$version' already exists locally" >&2
  exit 1
fi

for remote_tag in "${remote_tags[@]}"; do
  if [[ "$remote_tag" == "$version" ]]; then
    echo "error: tag '$version' already exists on origin" >&2
    exit 1
  fi
done

release_version="${version#v}"
short_commit="$(git rev-parse --short HEAD)"
if [[ "$release_version" == "$manifest_version" ]]; then
  commit_plan="none, manifest.json already has the selected version"
else
  commit_plan="release: $version"
fi

echo
echo "Release plan:"
echo "  project:          Omarchy Firewall"
echo "  version file:     manifest.json"
echo "  manifest version: $manifest_version -> $release_version"
echo "  tag:              $version"
echo "  branch:           $branch"
echo "  upstream:         $upstream"
echo "  current commit:   $short_commit"
echo "  checks:           make check"
echo "  commit:           $commit_plan"
echo "  push:             branch and tag to origin, atomically"
echo "  GitHub Release:   created by GitHub Actions with generated notes"
echo
printf "Proceed? [y/N] "
confirm=""
read -r confirm || true
case "$confirm" in
  y|Y|yes|YES) ;;
  *)
    echo "Aborted."
    exit 1
    ;;
esac

manifest_changed=0
if [[ "$release_version" != "$manifest_version" ]]; then
  python3 - "$manifest_version" "$release_version" <<'PY'
import json
from pathlib import Path
import sys

expected_version, release_version = sys.argv[1:]
path = Path("manifest.json")
manifest = json.loads(path.read_text(encoding="utf-8"))
if manifest.get("version") != expected_version:
    raise SystemExit("manifest version changed while preparing the release")
manifest["version"] = release_version
path.write_text(
    json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
    encoding="utf-8",
)
PY
  manifest_changed=1
fi

make check

changes="$(git status --porcelain=v1 --untracked-files=all)"
expected_changes=""
if (( manifest_changed )); then
  expected_changes=" M manifest.json"
fi

if [[ "$changes" != "$expected_changes" ]]; then
  echo "error: release preparation produced unexpected working tree changes" >&2
  git status --short
  exit 1
fi

if (( manifest_changed )); then
  git add manifest.json
  git commit -m "release: $version"
else
  echo "Manifest already contains version $release_version; no commit is needed."
fi

if [[ -n "$(git status --porcelain=v1 --untracked-files=all)" ]]; then
  echo "error: working tree changed before tagging" >&2
  git status --short
  exit 1
fi

git tag -a "$version" -m "Release $version"

if ! git push --atomic origin \
  "HEAD:refs/heads/${remote_branch}" \
  "refs/tags/${version}:refs/tags/${version}"; then
  echo "error: atomic push failed; the local commit and tag were kept" >&2
  exit 1
fi

echo
echo "Release tag $version was published with the branch."
echo "GitHub Actions will validate the tag and create the GitHub Release."
