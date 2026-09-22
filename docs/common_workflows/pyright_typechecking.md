# 🔍 Pyright Typechecking

We use [Pyright](https://microsoft.github.io/pyright/) (Microsoft’s fast static type checker) in **strict** mode. This ensures every function and variable has an explicit type, reducing runtime errors and catching mismatches early.

## Day-to-Day Workflows

### Running the Typechecker

To check all type annotations without running tests, simply run:

```bash
uv run pyright
```

This will type-check the entire project against the `pyrightconfig.json` (or `pyproject.toml` `[tool.pyright]`) configuration. (You can also run `make typecheck` if provided as a shortcut.) Pyright for Python is invoked just like the normal `pyright` CLI.

### Handling Strict Mode Issues

In strict mode, implicit `Any` types are disallowed, so Pyright will complain if it cannot infer a type. In such cases:

- **Annotate explicitly:** Add type hints (e.g., function parameters, variable declarations) so Pyright knows the types.
- **Use `typing.cast` or `assert` statements** to tell Pyright about dynamic types when needed.
- **As a last resort,** use `# type: ignore` on a line to silence errors (for example, when dealing with an untyped third-party library). However, relying on ignores should be minimized.

Pyright’s configuration (e.g. setting `"strict": true` for relevant paths) enables most strict checks by default. This means that, unless explicitly ignored, your code should have complete type coverage.
