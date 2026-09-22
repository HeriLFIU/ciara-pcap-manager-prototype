# 🚀 Release Please Automated Releases

We use Google’s [Release Please](https://github.com/googleapis/release-please) GitHub Action to automate version bumping, changelog generation, and GitHub Releases, based on our Conventional Commits.

## How It Works

1. **Merge PRs into `main`** using conventional commit messages (`feat:`, `fix:`, etc.).
1. Release Please scans the commit history in `main`, looking for Conventional Commits, and opens or updates a *Release PR* (titled like `chore: release vX.Y.Z`) that contains the new `CHANGELOG.md` entries and version bump.
1. As you merge more PRs, the bot continuously updates its pending Release PR with new changes.
1. **When ready to publish a release:** Approve and merge the Release PR. Release Please then automatically tags the repo and creates the GitHub Release for that version.

Release Please’s workflow ensures that releases are strictly driven by commit history. It relies on Conventional Commits to determine whether to bump patch, minor, or major versions.

## ⚠️ Critical Workflow Rule: Squash & Merge

To keep the history clear for Release Please, **always use “Squash and merge”** when merging your PRs in GitHub. The final squashed commit message **must** follow the Conventional Commit format (e.g. `feat: implement data parser`). Clean, single-commit merges help the bot correctly understand what changed; do not leave WIP commits in the history.
