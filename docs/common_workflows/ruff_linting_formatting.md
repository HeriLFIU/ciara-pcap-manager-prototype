# ✨ Ruff Linting & Formatting

We use [Ruff](https://docs.astral.sh/ruff/) as our ultra-fast Python linter and formatter. Ruff replaces tools like Flake8, Black, and isort, enforcing a strict, consistent style as configured in `pyproject.toml`.

## Day-to-Day Workflows

### Fast Auto-Formatting

Before committing changes, you should format your code to match project standards. To auto-format **all files** in the repository, run:

```bash
uv run ruff format .
```

This will apply fixes like sorting imports and formatting to the code according to our style rules. (We also provide a shortcut: `make format`, which typically runs the same command.)

### Checking for Lint Errors

To check for any lint errors **without modifying files**, run:

```bash
uv run ruff check .
```

This will list violations of Ruff’s rules in your code. It’s useful for seeing issues or as part of a CI step. (_For example, you might see unused-import errors or formatting issues._)

### Auto-Fixing Lint Errors

Ruff can automatically fix many issues for you. To run Ruff in “fix” mode:

```bash
uv run ruff check --fix .
```

This command will attempt safe fixes (like removing unused imports or reordering imports). (Our `make format` target often runs formatting **and** `--fix` sequentially.)

### Bypassing Rules (Use Sparingly)

On rare occasions where you have a good reason to ignore a rule, you can use `# noqa` comments. For example:

```python
import os  # noqa: F401
```

This ignores the “unused import” error (F401) for that line. Use these comments judiciously and document why the rule is bypassed.
