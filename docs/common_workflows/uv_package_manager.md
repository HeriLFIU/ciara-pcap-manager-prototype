# 📦 Managing Packages with uv

Our project uses [uv](https://docs.astral.sh/uv/), an extremely fast Python package and project manager written in Rust. It replaces traditional `pip`/`pip-tools`/`virtualenv` workflows by providing a single, integrated command set. **All dependency commands should be run at the root of the repository** where the `pyproject.toml` is located (so that `uv` finds the project).

## Day-to-Day Workflows

### Adding a Dependency

To add a new package to the project (which automatically updates `pyproject.toml` and installs it into the virtual environment), run:

```bash
uv add <package_name>
```

If it’s a development-only dependency (e.g. a testing or linting tool), add the `--dev` flag:

```bash
uv add --dev <package_name>
```

These commands will update the lock file and install the package in `.venv`.

### Removing a Dependency

To cleanly remove a package from both `pyproject.toml` and the virtual environment:

```bash
uv remove <package_name>
```

This removes it from your project’s dependencies and updates the lock file accordingly.

### Locking Dependencies

If you manually edit `pyproject.toml` or need to re-resolve the full dependency graph (for example, to update pinned versions), regenerate the lockfile. This creates or updates `uv.lock` to guarantee deterministic installs:

```bash
uv lock
```

_(You can also use our Makefile helper: `make lock`.)_

### Syncing the Environment

Whenever you pull changes from the repo and someone has updated dependencies, sync your local `.venv` to match the lockfile:

```bash
uv sync
```

This ensures you have exactly the same packages installed as defined in `uv.lock`.
