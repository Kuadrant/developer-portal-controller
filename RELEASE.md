# How to Release Developer Portal Controller

## Versioning and release branches

This project follows [Semantic Versioning](https://semver.org/) (`X.Y.Z`).
`main` keeps `VERSION ?= 0.0.0` in the Makefile and development chart placeholders.
Release versions are set only on `release-X.Y`, for example `release-0.3`.
Keep these branches after publication for patch releases; no development version
bump is needed on `main`.

## Prepare a release

1. Run [Automated Release](https://github.com/Kuadrant/developer-portal-controller/actions/workflows/automated-release.yaml)
   with:
   - **gitRef**: a branch, tag, or full 40-character commit SHA. Do not use an
     abbreviated SHA. Use `main` for a new minor stream and the existing
     `release-X.Y` branch for subsequent candidates, the final release, or patches.
   - **version**: the version without `v`, such as `0.3.0` or `0.3.0-rc.1`.
2. The workflow creates or reuses `release-X.Y` and opens a version PR from
   `prepare-release-X.Y.Z`. The topic branch deliberately has a different prefix
   from the protected maintenance branches so it can be pushed before PR checks
   exist. The PR updates the Makefile version, chart `version` and `appVersion`,
   and image expiry.
3. Have a maintainer review the PR and merge it after all required CI checks,
   including e2e, pass. The release commit must be the merged PR commit at the
   tip of the maintenance branch.
4. For a PR originating in this repository, the **Release** workflow publishes
   an annotated tag and a GitHub Release with generated notes. The tag push
   triggers the container image build. Fork PRs use the manual recovery path
   below after review and merge, because their PR events do not receive the
   publication secret.

Both preparation and publication require the repository's `KUADRANT_DEV_PAT`
secret. Publication uses that credential so the tag push can trigger the image
workflow. Required-check verification uses the read-only workflow token.

## Patch releases

Backport fixes through a PR against the existing `release-X.Y` branch. For
example:

```shell
git fetch upstream release-0.3
git switch --create backport/fix-description upstream/release-0.3
git cherry-pick --signoff <fix-commit>
git push origin backport/fix-description
gh pr create --repo Kuadrant/developer-portal-controller --base release-0.3
```

After that PR passes CI, is reviewed, and is merged, run **Automated Release**
with `gitRef=release-0.3` and `version=0.3.1`. Review and merge the resulting
version PR normally. Do not cut an older patch from `main`; it contains work for
the next minor.

## Manual preparation and publication recovery

If preparation fails, inspect whether the maintenance branch or version PR was
already created before retrying. Preserve existing maintenance branch history.
A manual preparation PR must make the same Makefile, chart, and expiry changes
as `.github/actions/prepare-release-branch`. Commit with `git commit --signoff`,
push only the topic branch to your fork, and open a PR against `release-X.Y`.

Existing maintenance branches may still contain an older automatic workflow;
use this recovery path from `main` for those branches.

After a release PR is reviewed and merged, recover a missed publication event
or publish a fork PR using **Release**, dispatched from **main** with that PR's
number:

```shell
gh workflow run release.yaml --repo Kuadrant/developer-portal-controller \
  --ref main -f pullRequest=<merged-release-pr-number>
```

The workflow verifies that the PR is merged into this repository's maintenance
branch, that its merge commit is still the branch tip, and that its required
checks pass. It checks out that exact commit, verifies its Makefile version
matches the maintenance stream, and publishes only `refs/tags/vX.Y.Z`.
An advanced branch, missing checks, failed query, or mismatched existing tag
stops publication. Do not change a published tag to recover a release.

If a matching tag already exists but the GitHub Release does not, recovery
reuses the tag. If the GitHub Release already exists, it is reported without
republishing; inspect whether it is published, draft, or a prerelease before
proceeding. A rerun does not retrigger an image build for an existing tag.

For an image build failure, inspect the run for the exact tag and commit before
rerunning that failed build. Check Quay first: if the expected image already
exists, verify it rather than rebuilding a published tag.

## Verify publication

Record the release PR, full merge SHA, tag, GitHub Release URL, image build run,
and Quay image digest. Check the tag resolves to the reviewed merge commit and
the build run matches both the tag and commit. Publication is complete only
when the image is available at
[Quay](https://quay.io/repository/kuadrant/developer-portal-controller?tab=tags).

For example, inspect a specific release with:

```shell
gh release view vX.Y.Z --repo Kuadrant/developer-portal-controller
gh run list --repo Kuadrant/developer-portal-controller \
  --workflow build-image.yaml --event push --branch vX.Y.Z --commit <merge-sha>
curl -fsS 'https://quay.io/api/v1/repository/kuadrant/developer-portal-controller/tag/?specificTag=vX.Y.Z'
```

## Post-release

Keep `release-X.Y` available for patch PRs and leave the placeholders on `main`.
Notify the [kuadrant-operator](https://github.com/Kuadrant/kuadrant-operator)
maintainers to update the controller dependency in `release.yaml` for the next
operator release. The controller is bundled as part of the operator; see its
[release process](https://github.com/Kuadrant/kuadrant-operator/blob/main/RELEASE.md).

## Testing release tooling

The tests use fake GitHub responses and temporary local Git repositories. They
do not publish tags, releases, or images to external services:

```shell
node --test utils/release/tests/*.test.cjs
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s utils/release/tests
shellcheck utils/release/publish-release.sh
actionlint .github/workflows/release.yaml .github/workflows/automated-release.yaml
```
