# 🧹 PreK Quality Checks

We use [PreK](https://github.com/j178/prek) (a fast Rust port of pre-commit) to manage our Git hooks. PreK runs linters, formatters, type-checkers, and other checks automatically whenever we commit, preventing bad code from entering the repo.

## Day-to-Day Workflows

### Automatic Execution on Commit

After setup (`prek install`), PreK will run automatically on `git commit`. It inspects the files staged in Git and executes the configured hooks only on those files. This means you get lint/typecheck feedback immediately before a commit is recorded.

### Manual Execution (All Files)

If you change hook configurations or want to run all hooks on the entire codebase (for example, before opening a PR), do:

```bash
uv run prek run --all-files
```

This will run all hooks across all files, not just the staged ones. (We also provide a Makefile shortcut: `make lint`.)

### Handling Hook Failures

- **Auto-fixing hooks** (e.g. Ruff or trailing-whitespace hooks) will automatically fix issues in place and then abort the commit. In that case, simply `git add` the fixed files and try committing again.
- **Manual-fix hooks** (e.g. Pyright errors) will print error messages and exit non-zero. You need to correct the code as instructed, stage the changes, and re-run the commit.

### Updating Hooks

To update all hook dependencies to their latest versions, run:

```bash
uv run prek autoupdate
```

This will update all entries in `.pre-commit-config.yaml` (or `prek.toml`) to the latest commits. (Again, we often alias this as `make update-hooks`.)
