# ⚙️ Project Setup

## Explanation

For minimal CI, linting, formatting, and much more, the .pre-commit-config.yaml file can be copied, and you can run one of two scripts depending on your setup. You can run scripts/interactive/prek-setup.interactive.sh or scripts/non-interactive/setup-prek.sh. The interactive one is currently much better. Prek is the Rust rewrite of pre-commit, a tool that can run automated workflows whenever you perform actions with Git. It uses Git hooks; you can also use it with GitHub Actions or whatever other tool is being used to manage CI, like Jenkins. It is very useful, highly portable, and customizable; you can even use PreK in C projects and JavaScript projects.

## How a general setup should look

### Step 1: Clone the Repository

```bash
git clone https://github.com/HeriLFIU/ciara-pcap-prototype.git.git
cd ciara-pcap-prototype
```

Ensure you are at the root of the repository in the next step.

### Step 2: Run the Setup Wrapper

We have a `Makefile` to bootstrap the project environment. Make sure you have `make` installed, then run:

```bash
make setup
```

This setup step does several things automatically:

- Validates that you’re in the project root (where `pyproject.toml` lives).
- Runs `uv sync` to create and populate the virtual environment `.venv` with the locked dependencies.
- Installs the PreK Git hooks (`prek install`).
- Installs Commitizen hooks (so `cz commit` or `git commit` triggers the wizard).

After setup completes, your environment is fully synchronized and ready for development.

## 🪟 Developing on Windows

The project is built and tested on Linux, but it runs on Windows. Use **Git Bash
or WSL2** — `make` and the setup scripts need a POSIX shell.

### What is handled automatically

`--disable-socket` (in `pyproject.toml`'s `addopts`) blocks socket creation for
every address family except AF_UNIX. Windows has no AF_UNIX event loop, so
`asyncio` builds its self-pipe with `socket.socketpair()`, which falls back to a
loopback TCP pair — meaning every async test would fail before it started.

`tests/conftest.py` detects Windows and marks each test with pytest-socket's
`allow_hosts` instead: sockets can be created, but `connect()` is restricted to
loopback, so outbound network calls are still blocked. POSIX platforms keep the
stricter `--disable-socket` behaviour. No configuration is needed either way.

### Hooks that need extra toolchains

Most hooks are pure Python (`shellcheck` and `checkov` included) and work
everywhere. A few need a toolchain prek has to fetch or find:

<!-- A list rather than a table: which rows appear depends on the hook groups
     selected, and a table's column padding depends on its widest row. -->

- `oxipng` (`rust`) — Rust toolchain, which prek downloads for you.
- `checkmake` (`golang`) — Go toolchain, which prek downloads for you.
- `hadolint` (`system`) — the `hadolint` binary must already be on your `PATH`.

If any of them cannot install on your machine, skip them per-invocation with the
`SKIP` environment variable — it is honoured by prek during git hook runs:

```bash
SKIP=oxipng,checkmake git commit -m "feat(parser): add flow header parsing"
```

The same names work as `prek run --skip oxipng --skip checkmake`. CI runs on
Linux, so anything skipped locally is still enforced on your pull request.
