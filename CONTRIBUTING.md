# Contributing

For general Kuadrant contribution guidance, see the [Kuadrant contributing guide](https://kuadrant.io/contributing/).

This document covers the automated governance rules enforced in this repository and the project-specific workflow for getting a contribution merged.

## Issue Triage

All new issues are automatically labelled `triage/needs-triage`. A maintainer will review and move the issue to `triage/accepted` once it has been discussed and prioritised.

| Label | Meaning |
|---|---|
| `triage/needs-triage` | New issue, awaiting maintainer review |
| `triage/accepted` | Reviewed, prioritised, and ready for work |

Only Kuadrant org members can change triage labels. If a non-member attempts to add or remove a triage label, the change is automatically reverted.

## Pull Request Requirements

Every PR from an external contributor must:

1. **Link to an issue** — use `Fixes #123` or `Closes #123` in the PR description, or link it via the GitHub sidebar.
2. **Link to a triaged issue** — the linked issue must carry the `triage/accepted` label before the PR is opened.
3. **Not duplicate existing work** — if another contributor already has an open PR for the same issue, your PR will be auto-drafted until that one is resolved.

PRs that do not meet these requirements are automatically closed with an explanatory comment. Your branch is kept intact, so you can reopen once the requirements are satisfied.

This enforcement is implemented by the [Kuadrant contributor governance workflow](https://github.com/Kuadrant/.github/blob/main/.github/workflows/contributor-governance.yml), called from [`.github/workflows/contributor-governance.yml`](.github/workflows/contributor-governance.yml) in this repo.
