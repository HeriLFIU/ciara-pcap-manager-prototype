# 🏗️ Building & Managing the Project

We manage our project using `uv`, so all commands (even running scripts) should go through `uv run`. This ensures that code always uses the exact locked dependencies and Python interpreter.

## Day-to-Day Workflows

### Running Project Scripts

Instead of activating a virtualenv manually, prefix your commands with `uv run`. For example, to execute our main application script:

```bash
uv run src/ciara_pcap_manager_prototype/main.py
```

This runs the script inside the project’s environment, using the dependencies defined in our lockfile. (Under the hood, `uv run` ensures `.venv` is set up before running the command.)

### Building the Package

If you need to produce distributable artifacts (a source tarball and a binary wheel) for inspection or release, use:

```bash
uv build
```

This uses PEP 517 to build the package and outputs `.tar.gz` and `.whl` files into the `dist/` directory. You can then manually inspect or deploy these artifacts as needed.

> **Note:** `pyproject.toml` carries the `Private :: Do Not Upload` classifier, which makes an accidental `uv publish` fail rather than leak the package. Remove it deliberately when you actually intend to publish.
