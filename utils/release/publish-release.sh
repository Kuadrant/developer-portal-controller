#!/usr/bin/env bash
set -euo pipefail

# Run from the checked-out release commit; tooling stays on main.
: "${RELEASE_BRANCH:?}" "${RELEASE_SHA:?}" "${GH_REPO:?}" "${GH_TOKEN:?}"
test "$(git rev-parse HEAD)" = "$RELEASE_SHA"
git fetch --no-tags origin "refs/heads/${RELEASE_BRANCH}"
test "$(git rev-parse FETCH_HEAD)" = "$RELEASE_SHA"

VERSION=$(sed -n 's/^VERSION ?= //p' Makefile)
[[ "$VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[a-zA-Z0-9.-]+)?$ ]]
STREAM=${VERSION%%-*}
STREAM=${STREAM%.*}
if [[ "$RELEASE_BRANCH" != "release-$STREAM" && "$RELEASE_BRANCH" != "release-v$STREAM" ]]; then
  echo "Version $VERSION does not match $RELEASE_BRANCH" >&2
  exit 1
fi
[[ "$VERSION" != 0.0.0 ]]
TAG=v$VERSION

# A successful response is required; a network error is not release absence.
RELEASES=$(gh api --paginate --slurp "repos/$GH_REPO/releases")
RELEASE_EXISTS=$(jq -er --arg tag "$TAG" 'if any(.[][]; .tag_name == $tag) then "yes" else "no" end' <<<"$RELEASES")

if git show-ref --verify --quiet "refs/tags/$TAG"; then
  test "$(git rev-parse "refs/tags/$TAG^{commit}")" = "$RELEASE_SHA"
else
  test "$RELEASE_EXISTS" = no
  git config user.name 'github-actions[bot]'
  git config user.email '41898282+github-actions[bot]@users.noreply.github.com'
  git tag -a "$TAG" "$RELEASE_SHA" -m "Release $TAG"
  git push origin "refs/tags/$TAG:refs/tags/$TAG"
fi

if [[ "$RELEASE_EXISTS" == yes ]]; then
  gh release view "$TAG"
  echo 'Release already exists; inspect its state and image workflow before further recovery.'
  exit 0
fi

ARGS=(--verify-tag --title "$TAG" --generate-notes)
if [[ "$VERSION" == *-* ]]; then ARGS+=(--prerelease); fi
gh release create "$TAG" "${ARGS[@]}"
