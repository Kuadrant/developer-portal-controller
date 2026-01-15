# How to Release Developer Portal Controller

## Versioning

This project follows [Semantic Versioning](https://semver.org/) (X.Y.Z).

The version is defined in the `Makefile`:
```makefile
VERSION ?= X.Y.Z
```

**Important:** The `main` branch always has `VERSION ?= 0.0.0` as a placeholder. The actual version is only set on release branches (e.g., `release-v0.1`). This follows the same pattern as [kuadrant-operator](https://github.com/Kuadrant/kuadrant-operator). When building release images, the version is read from the release branch where the automated workflow updated it.

## Automated Workflow (Recommended)

_**IMPORTANT:**_
For RC2+ or patch releases, set `gitRef` to the existing release branch (e.g., `release-v0.1`), not `main`.
The workflow picks up all history from the specified gitRef - cherry-pick any required fixes to the release branch before triggering the workflow.

### Notes
* The automated workflow is best suited for RC1 of a new point release from `main`.
* For patch releases (e.g., 0.1.1): Cherry-pick only the bug fix to the release branch, then run the workflow with `gitRef: release-v0.1`.
* It's not possible to cherry-pick commits within the workflow - it will include all history from the gitRef.

### Steps

1. **Run the [Automated Release](https://github.com/Kuadrant/developer-portal-controller/actions/workflows/automated-release.yaml) workflow** filling the following fields:
   - **gitRef**: Select the branch/tag/commit where you want to cut a release from (usually `main`)
   - **version**: The version to release (e.g., `0.1.0` or `0.1.0-alpha-1`)

2. **Review and merge the PR**:
   - The workflow creates a PR that updates the VERSION in the Makefile
   - Review the changes and merge the PR

3. **Automatic post-merge actions**:
   - Once merged, the Release workflow automatically:
     - Creates a git tag (e.g., `v0.1.0`)
     - Creates a GitHub release with auto-generated release notes
     - Triggers the image build workflow

4. **Verify the release**:
   - Check the [GitHub Actions](https://github.com/Kuadrant/developer-portal-controller/actions) workflows completed successfully
   - Verify the image is available at [quay.io](https://quay.io/repository/kuadrant/developer-portal-controller?tab=tags)

## Patch Releases

To release a patch (e.g., `0.1.1` after `0.1.0` with a bug fix from `main`):

1. **Cherry-pick the fix to the release branch**:
   ```bash
   git checkout release-v0.1
   git pull origin release-v0.1
   git cherry-pick <commit-sha>    # Only the bug fix, not new features
   git push origin release-v0.1
   ```

2. **Run the Automated Release workflow**:
   - **gitRef**: `release-v0.1` (the release branch, NOT main)
   - **version**: `0.1.1`

3. **Review and merge the PR**, then the release will be created automatically.

> **Note**: Patch releases should only include bug fixes, not new features. New features go into the next minor release (e.g., `0.2.0`).

## Manual Workflow

If the automated workflow is not suitable, you can release manually:

1. **Update the VERSION** in the [Makefile](./Makefile):
   ```makefile
   VERSION ?= X.Y.Z
   ```

2. **Commit the version change**:
   ```bash
   git commit -m "Release vX.Y.Z"
   ```

3. **Create and push a git tag**:
   ```bash
   git tag vX.Y.Z
   git push origin main --tags
   ```

4. **[GitHub Actions](https://github.com/Kuadrant/developer-portal-controller/actions/workflows/build-image.yaml) will automatically**:
   - Build image
   - Push the image to `quay.io/kuadrant/developer-portal-controller:vX.Y.Z`

5. **Verify the release**:
   - Check the [GitHub Actions](https://github.com/Kuadrant/developer-portal-controller/actions) workflow completed successfully
   - Verify the image is available at [quay.io](https://quay.io/repository/kuadrant/developer-portal-controller?tab=tags)

## Post-Release

After releasing a new version, notify the [kuadrant-operator](https://github.com/Kuadrant/kuadrant-operator) maintainers to update the `developer-portal-controller` dependency version in `release.yaml` for the next kuadrant-operator release.

## Bundled Releases

The developer-portal-controller is bundled as part of the kuadrant-operator release. When a new kuadrant-operator version is released, it includes a specific version of this controller.

For details on the kuadrant-operator release process, see the [kuadrant-operator RELEASE.md](https://github.com/Kuadrant/kuadrant-operator/blob/main/RELEASE.md).
