# AGENTS.md

Operating manual for AI coding agents working in this repository.

This project was generated from a **Copier template** and is still linked to it
through `.copier-answers.yml`. The tooling — `uv`, `prek`, `ruff`, `pyright`,
`pytest`, `commitizen`, and `release-please` — comes from that template and can be
refreshed with `copier update`. Treat the configuration files as the primary
source of truth. See [§9](#9-this-project-and-its-copier-template) before
changing anything the template owns.

Human-facing documentation lives in [README.md](README.md) and [docs/](docs).
This file exists because several of those workflows are **interactive by design**
and will hang or corrupt state when driven by an agent. Everything below is the
non-interactive path.

______________________________________________________________________

## 1. The rules that matter most

1. **Never run a bare `git commit`.** It launches the Commitizen wizard and
   blocks forever. Always pass a valid Conventional Commit message with `-m`.
   See [§4](#4-committing-without-the-commitizen-wizard).
1. **Never commit directly to `main` or `master`.** The `no-commit-to-branch`
   hook rejects it. Create a branch first. See [§5](#5-branching-and-pull-requests).
1. **Never run `scripts/interactive/*.sh`.** They use bash `select` menus and
   will hang. Use `scripts/non-interactive/*.sh` instead.
1. **Never assume `make` exists.** On Windows it frequently is not installed.
   Use the underlying `uv run` commands. See [§3](#3-platform-differences-macos--linux--windows).
1. **Never use `git commit --no-verify` to get unstuck.** It disables the secret
   scanner, the formatters, and the commit-message validator all at once, which
   silently breaks the release automation. See [§4.4](#44-the-escape-hatch-and-why-you-should-not-use-it).
1. **Never edit `.copier-answers.yml` by hand.** It is a factual record of what
   generated this project. Editing it corrupts every future `copier update`.
   See [§9](#9-this-project-and-its-copier-template).

______________________________________________________________________

## 2. Repository layout

```text
ciara-pcap-prototype/
├── .github/
│   ├── ISSUE_TEMPLATE/          # Issue templates (titles are Conventional Commits)
│   └── workflows/
│       ├── ci.yml               # prek-checks → tests / benchmarks / profiling
│       └── release-please.yml   # Opens the release PR from commit history
├── archive/                     # Reference-only. Not wired into anything.
│   ├── ci.allfiles.yml          # Alternative CI that lints the WHOLE repo
│   └── prek.unused.ntoml        # Abandoned prek.toml port of the hook config
├── docs/
│   ├── common_workflows/        # Task-oriented guides
│   └── concepts/                # Conventional Commits, SemVer, Boy Scout Rule
├── scripts/
│   ├── interactive/             # Agents must NOT run these (bash `select`)
│   └── non-interactive/         # Safe for agents and CI
├── src/ciara_pcap_manager_prototype/          # Application source
├── tests/                       # conftest.py + tests/unit/
├── .copier-answers.yml          # Template link + answers — NEVER hand-edit
├── .gitattributes               # Forces eol=lf everywhere, including Windows
├── .pre-commit-config.yaml      # The heart of the repo: the prek hooks
├── Makefile                     # Developer CLI. Requires bash + GNU make.
├── pyproject.toml               # Deps, ruff, pyright, pytest, coverage config
└── uv.lock                      # Deterministic lockfile — never hand-edit
```

### 2.1 Generated paths: never edit, never commit

`.venv/`, `.reports/`, `.coverage`, `.pytest_cache/`, `.ruff_cache/`,
`.benchmarks/`, `__pycache__/`, `dist/`, `scalene-profile.*`. All are covered by
`.gitignore` and by [.agentignore](.agentignore).

`uv.lock` **is** committed but is machine-generated: change it with `uv add`,
`uv remove`, or `uv lock`, never by editing the file.

`tests/unit/__snapshots__/*.ambr` are syrupy snapshots. Regenerate with
`uv run pytest tests --snapshot-update`; do not hand-edit them.

`.copier-answers.yml` **is** committed and is maintained by Copier. See
[§9](#9-this-project-and-its-copier-template).

______________________________________________________________________

## 3. Platform differences (macOS / Linux / Windows)

CI runs exclusively on `ubuntu-latest`, and the project is verified to work on
macOS and Windows. The differences are real and an agent will trip on them.

### 3.1 Support matrix

| Concern                        | Linux              | macOS                    | Windows                                |
| ------------------------------ | ------------------ | ------------------------ | -------------------------------------- |
| Shell for scripts and Makefile | native bash        | native bash              | **Git Bash or WSL2 required**          |
| `make` available               | usually            | usually (Xcode CLT)      | **often absent — probe first**         |
| Virtualenv binaries            | `.venv/bin/`       | `.venv/bin/`             | `.venv/Scripts/`                       |
| `uv run <cmd>`                 | yes                | yes                      | yes (use this; it hides the row above) |
| `sed -i` flavour               | GNU                | BSD (needs an empty arg) | GNU (Git Bash)                         |
| `shellcheck` auto-install      | apt/dnf/pacman/apk | Homebrew                 | scoop/choco, else skipped              |
| pytest network isolation       | `--disable-socket` | `--disable-socket`       | loopback-only `allow_hosts`            |
| Working-tree line endings      | LF                 | LF                       | **LF, forced by `.gitattributes`**     |

### 3.2 Prefer `uv run` over everything else

`uv run <command>` resolves the interpreter and the locked dependencies
identically on all three platforms and sidesteps the `bin` vs `Scripts` split
entirely. It is the single most portable way to invoke anything in this repo.

```bash
uv run pytest tests
uv run ruff check .
uv run pyright
uv run prek run --all-files
```

Do **not** activate the virtualenv, and do not call `.venv/bin/python`
directly — that path does not exist on Windows.

### 3.3 The Makefile is a bash program

`Makefile` opens with `SHELL := /bin/bash` and `.SHELLFLAGS := -eu -o pipefail -c`.
It will not run under `cmd.exe` or PowerShell. On Windows it needs Git Bash or
WSL2, **and** a `make` binary, which Git for Windows does not ship.

Before using a `make` target, probe for it:

```bash
command -v make >/dev/null 2>&1 && make lint || uv run prek run --all-files
```

Every target is a thin wrapper. The direct equivalents:

| Make target         | Portable equivalent                                                                                                     |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `make setup`        | see [§3.4](#34-bootstrapping-a-fresh-clone)                                                                             |
| `make lint`         | `uv run prek run --all-files`                                                                                           |
| `make format`       | `uv run ruff check --fix . && uv run ruff format .`                                                                     |
| `make typecheck`    | `uv run pyright`                                                                                                        |
| `make test`         | `uv run pytest tests`                                                                                                   |
| `make lock`         | `uv lock`                                                                                                               |
| `make update-hooks` | `uv run prek autoupdate`                                                                                                |
| `make clean`        | delete the generated paths in [§2.1](#21-generated-paths-never-edit-never-commit)                                       |
| `make profile`      | `uv run scalene run --profile-all --reduced-profile src/ciara_pcap_manager_prototype/main.py` (opens a browser — avoid) |
| `make report`       | see [§10](#10-reading-ci--analysis-feedback) — expensive, run deliberately                                              |

### 3.4 Bootstrapping a fresh clone

`make setup` runs these scripts in order. Run them directly when `make` is
missing — they are all non-interactive:

```bash
./scripts/non-interactive/is-git-project-root.sh      # asserts CWD == git root
uv sync                                               # hydrate .venv from uv.lock
./scripts/non-interactive/install-deps.sh             # best-effort shellcheck (OS-aware)
./scripts/non-interactive/setup-prek.sh               # uv run prek install
./scripts/non-interactive/install-commitizen-hooks.sh # see the warning below
```

Two warnings for agents:

- `install-deps.sh` may invoke `sudo` on Linux. In a sandbox without a TTY that
  will fail or hang. It is *best-effort* — every hook ships its own pinned
  binary — so skipping it is safe.
- `install-commitizen-hooks.sh` downloads the interactive `prepare-commit-msg`
  and `post-commit` hooks into `.git/hooks/`. **This is precisely the machinery
  that traps agents.** If you are bootstrapping an environment purely to run
  checks, skip this script; the `commit-msg` validation hook installed by
  `prek install` still enforces Conventional Commits.

### 3.5 Line endings

`.gitattributes` sets `* text=auto eol=lf`, which overrides `core.autocrlf` and
materialises LF in the working tree on Windows too. This is deliberate:
yamllint's `new-lines: unix` rule and the `mixed-line-ending --fix=lf` hook both
fail on CRLF.

When writing files, emit LF. Do not "fix" `.gitattributes`, do not set
`core.autocrlf=true`, and do not use tools that rewrite files with CRLF.

### 3.6 Windows and pytest network isolation

`pyproject.toml` passes `--disable-socket`, which blocks socket *creation* for
every family except `AF_UNIX`. Windows has no `AF_UNIX` event loop, so asyncio
builds its self-pipe from `socket.socketpair()` — a loopback TCP pair — and
every async test would die before starting.

`tests/conftest.py` detects `sys.platform == "win32"` and applies pytest-socket's
`allow_hosts` marker (`127.0.0.1`, `::1`) to every collected item instead:
sockets may be created, but `connect()` is restricted to loopback. POSIX keeps
the stricter behaviour.

Consequence for test authors: **a test that asserts network blocking must accept
both failure modes.** `tests/unit/test_parser.py::test_network_isolation_is_active`
does this by asserting `pytest.raises(RuntimeError)` — the common base class of
the creation-blocked error on POSIX and the connect-blocked error on Windows. Do
not narrow it to a platform-specific exception type.

### 3.7 Hooks that need a non-Python toolchain

Most hooks are pure Python and run everywhere. These are not:

- `oxipng` (rust) — Rust toolchain, which prek downloads.
- `checkmake` (golang) — Go toolchain, which prek downloads.
- `hadolint` (system) — `hadolint` must already be on `PATH`.

`hadolint` is inert until the repo contains a `Dockerfile`. If any of these
cannot install locally, skip them for that invocation — CI runs on Linux and
still enforces them:

```bash
uv run prek run --all-files --skip oxipng --skip checkmake --skip hadolint
```

`SKIP` as an environment variable works during git hook runs:

```bash
SKIP=oxipng,checkmake git commit -m "feat(parser): add flow header parsing"
```

### 3.8 Network access

`prek` downloads and builds a pinned environment per hook on first run. This is
slow (minutes) and requires network access. In an offline sandbox `prek` will
fail — run `uv run ruff check .`, `uv run pyright`, and `uv run pytest tests`
directly instead, and say so in your report rather than claiming a clean run.

______________________________________________________________________

## 4. Committing without the Commitizen wizard

### 4.1 What actually happens

After setup, `.git/hooks/prepare-commit-msg` is Commitizen's hook. Its
logic, from upstream:

1. Run `cz check --commit-msg-file <file>`.
1. **If that exits 0 — the message is already a valid Conventional Commit — the
   hook returns immediately and no wizard runs.**
1. Otherwise, it reopens stdin from `/dev/tty` and launches the interactive
   `cz commit` wizard.

Step 3 is fatal for an agent: with no controlling terminal the hook either
raises while opening `/dev/tty` or blocks forever waiting on input that will
never arrive.

### 4.2 The correct approach: write a valid message

The wizard is *only* a fallback for an invalid message. Supply a good one and it
never appears. This is the supported agent path — no flags, no bypass.

```bash
git commit -m "feat(parser): add flow header parsing"
```

The exact pattern Commitizen enforces, as printed by `cz check` on failure:

```text
(build|bump|chore|ci|docs|feat|fix|perf|refactor|revert|style|test)(\(\S+\))?!?: ([^\n\r]+)((\n\n.*)|(\s*))?$
```

Which means:

- **Type is mandatory** and must be one of exactly those twelve.
- **Scope is optional**, in parentheses, no whitespace inside: `feat(ci):`.
- **`!` before the colon** marks a breaking change and triggers a MAJOR bump.
- **A space after the colon**, then a non-empty subject on one line.
- If there is a body it must be separated by **one blank line**.

Multi-line messages: repeat `-m`, which git joins with a blank line.

```bash
git commit -m "fix(conftest): restrict sockets to loopback on Windows" \
           -m "asyncio builds its self-pipe from socket.socketpair() on Windows, which --disable-socket rejects before any async test can start."
```

Or write the message to a file and use `-F`:

```bash
git commit -F .git/COMMIT_MSG_DRAFT
```

Validate a draft before committing — exit 0 means the wizard will not fire:

```bash
uv run cz check --commit-msg-file <path>
```

### 4.3 Commands agents must never invoke

| Command                                           | Why                                                 |
| ------------------------------------------------- | --------------------------------------------------- |
| `git commit` (no `-m` or `-F`)                    | Empty message fails `cz check`, so the wizard opens |
| `git commit -m ""`                                | Same as above                                       |
| `cz commit`, `cz c`, `git cz`                     | The wizard itself                                   |
| `git commit --amend` without `-m`                 | Reruns `prepare-commit-msg`, so the wizard opens    |
| `git rebase -i`, `git add -i`                     | Interactive editors                                 |
| `./scripts/interactive/prek-setup.interactive.sh` | bash `select` menu                                  |
| `make profile`                                    | Launches a browser UI and never exits               |

`make profile-export` is marked broken in the Makefile itself. Leave it alone.

### 4.4 The escape hatch, and why you should not use it

`git commit --no-verify` skips **every** hook, not just Commitizen: gitleaks
secret scanning, ruff formatting, pyright, the fast pytest run, and the
`commit-msg` Conventional Commit validator. A non-conventional commit that
reaches `main` is invisible to Release Please, so the change silently never
appears in the changelog and never triggers a version bump.

Writing a valid message per [§4.2](#42-the-correct-approach-write-a-valid-message)
costs nothing and keeps every gate intact. Use `--no-verify` only when a human
explicitly asks for it, and state plainly in your report that the checks were
bypassed.

If you need to skip *specific* hooks — an unavailable toolchain, say — use
`SKIP=hook1,hook2`, which leaves everything else running.

______________________________________________________________________

## 5. Branching and pull requests

The `no-commit-to-branch` hook is configured with
`args: ["--branch", "main", "--branch", "master"]` at the `pre-commit` stage.
Committing on either branch fails, by design.

```bash
git switch -c feat/flow-header-parsing
# ... edit ...
git add -A
git commit -m "feat(parser): add flow header parsing"
```

CI passes `--skip no-commit-to-branch` so the hook does not block the pipeline.

Merging is **Squash and Merge only**. The squashed title becomes the commit on
`main`, and it is the only thing Release Please reads. A merge commit or a
non-conventional squash title means the change never lands in a release. PR
titles therefore follow the same Conventional Commit grammar as commits.

______________________________________________________________________

## 6. Running the quality gates

Run these before declaring work finished, in rough order of cost:

```bash
uv run ruff format .                       # format
uv run ruff check --fix .                  # lint + safe autofixes
uv run pyright                             # strict type check
uv run pytest tests                        # full suite + coverage
uv run prek run --all-files                # everything CI runs
```

Targeted prek runs, useful while iterating:

```bash
uv run prek run --all-files ruff pyright   # named hooks only
uv run prek run --last-commit              # only files touched by HEAD
uv run prek run --from-ref main --to-ref HEAD
```

The last form is what CI uses — it lints only the PR's diff. This repo follows
the **Boy Scout Rule**: checks apply to changed files, not the whole tree, so
legacy code does not permanently redden the pipeline. Do not reformat untouched
files as a courtesy; it inflates the diff and defeats the design.

### 6.1 What CI enforces

`.github/workflows/ci.yml`, on push to `main`/`master` and on every PR:

1. **`prek-checks`** — all hooks against the PR diff. Gates everything else.
1. **`comprehensive-tests`** — full pytest with coverage, then `diff-cover` with
   `--fail-under=50`. **50% coverage is required on changed lines only.**
   New code needs tests; untouched legacy code is not penalised.
1. **`performance-benchmarks`** — `pytest -n 0 --benchmark-enable --benchmark-only`.
1. **`profiling`** — Scalene against `src/ciara_pcap_manager_prototype/main.py`, uploaded as an artifact.

Fork PRs get a read-only token, so the coverage-comment step is skipped by
design. The numbers still appear in the job log, step summary, and artifacts.

______________________________________________________________________

## 7. Testing conventions

`[tool.pytest.ini_options]` bakes a lot into `addopts`; a bare `uv run pytest`
already carries all of it.

- `pythonpath = ["src"]` — import as `from ciara_pcap_manager_prototype.parser import ...`, never with a
  `src.` prefix.
- `-n auto` (xdist) — tests must be **order-independent and parallel-safe**. No
  shared temp files, no module-level mutable state.
- `pytest-randomly` shuffles order every run. A test that only passes in a fixed
  order is a broken test.
- `--strict-markers` and `--strict-config` — an unregistered marker is an error.
- `--timeout=60` per test; the `pytest-fast` prek hook tightens it to 30.
- `--disable-socket` — **no network in tests**. Mock it. See
  [§3.6](#36-windows-and-pytest-network-isolation) for the Windows variant.
- `asyncio_mode = "auto"` — `async def test_*` needs no decorator.
- Benchmarks are disabled by default (`--benchmark-disable`); enable them
  explicitly with `-n 0 --benchmark-enable --benchmark-only`.
- `--cov=ciara_pcap_manager_prototype` is hardcoded. **Renaming the package requires updating this**
  — and the right way to rename is through Copier
  ([§9](#9-this-project-and-its-copier-template)), not by hand.
- `TESTING_MODE=1` is injected via `pytest-env`.
- `pytest-deadfixtures` runs as a hook: an unused fixture fails the commit.

Coverage output lands in `.reports/` (XML + HTML). Never commit it.

______________________________________________________________________

## 8. Code style the linters will actually reject

Ruff runs a very large rule set at `line-length = 88`, `target-version = py312`,
double quotes. Pyright runs in **strict** mode over `src` and `tests`. The rules
below are the ones agents violate most often:

- **`D` (pydocstyle)** — every public module-level function, class, and method
  needs a docstring. `D100`/`D104` (module/package) are exempted; nothing else
  is. Tests are exempt from `D101`/`D102`/`D103`.

- **`ANN` (annotations)** — every parameter and return type must be annotated,
  including `-> None`.

- **`ERA` (eradicate)** — **commented-out code is a lint error.** Delete dead
  code; do not park it in a comment.

- **`T20`** — no `print()` in `src/`. Use the module `logger`. Allowed in tests.

- **`PTH`** — use `pathlib`, not `os.path`.

- **`EM`** — no string literal directly inside `raise`. Assign it first:

  ```python
  msg = "flow header is empty"
  raise ValueError(msg)
  ```

- **`S` (bandit)** — security scanning. `assert` is allowed only under `tests/`.

- **`BLE` and `TRY`** — no bare or blind `except`; follow tryceratops conventions.

- **`FBT`** — boolean positional arguments are rejected; make them keyword-only.

- **`TCH`** — type-only imports belong under `if TYPE_CHECKING:`.

Pyright strict additionally forbids implicit `Any`. Prefer real annotations;
`typing.cast` and `# type: ignore` are last resorts and should carry a reason.

Beyond Python: the enabled hook groups also cover `shellcheck` plus `shfmt -i 4` on shell, `yamllint --strict` on YAML, `mdformat` plus `markdownlint` on Markdown, `taplo` on TOML, `actionlint` on workflows, `checkmake` on the Makefile, `typos` and `codespell` on prose, and `gitleaks` on everything.
Write conservatively and let the formatters settle the rest.

______________________________________________________________________

## 9. This project and its Copier template

This project was generated by [Copier](https://copier.readthedocs.io/). The link
to the template lives in `.copier-answers.yml`, which records the template
source, the exact template version (`_commit`), and every answer used.

### 9.1 The one rule

**Never edit `.copier-answers.yml` by hand, and never invent values in it.**
Copier treats it as a factual record of what produced the files on disk. Editing
it makes every future `copier update` merge against a state that never existed.
If it is wrong, restore it from git history and fix it through Copier.

### 9.2 Renaming the package, or changing any other answer

Do not do this by hand. The package name alone appears in `pyproject.toml`
(`[project] name`, `--cov=`), the `src/` directory name, every
test import, the Makefile profiling paths, and the CI Scalene step. Miss one
and coverage silently measures nothing.

Re-run Copier instead, and let it rewrite all of them:

```bash
git status                      # must be clean first
copier update --defaults --data package_name=new_name
git diff                        # review before committing
```

The same applies to `line_length`, `python_version`, `license_id`,
`diff_cover_threshold`, and every other answer. `copier update --help` lists the
flags.

### 9.3 Pulling in template improvements

```bash
copier update            # from a clean tree; three-way merges your own edits
copier update --pretend  # dry run, writes nothing
```

Conflicts arrive as `<<<<<<<` markers, exactly like a git merge. Resolve them
before committing — the `check-merge-conflict` hook will otherwise fail the
commit, which is the intended safety net. Do not bypass it.

The full workflow is in
[docs/common_workflows/copier_template.md](docs/common_workflows/copier_template.md).

### 9.4 Editing files the template owns

Anything the template generates can be edited freely — `copier update` replays
your edits on top of the new version. But prefer changing the *answer* over
changing the *output* when an answer exists for it, because a hand edit becomes
a permanent conflict site on every future update.

`[project] classifiers` contains `Private :: Do Not Upload`, which blocks
accidental PyPI publication. Remove it deliberately, never incidentally.

______________________________________________________________________

## 10. Reading CI & analysis feedback

Most checks print everything you need to the terminal. A few produce
*measurements* instead: the full suite with coverage, the micro-benchmarks,
and the Scalene profiler. When a claim depends on a number, read the artifact
rather than assuming.

**These runs are expensive.** They are deliberately not part of the commit hooks.
Run them before a release, when a change is performance-sensitive, when coverage
on new code is in question, or when asked — not on every edit, and never in a
loop.

```bash
make report     # full suite → coverage + JUnit XML in .reports/
make bench      # benchmarks only, serial, JSON output
make analyze    # both
```

Read the small files first, and extract rather than loading whole files:

```bash
grep -E "^\S+\.py +[0-9]+ +[0-9]+ +[0-9]+%" .reports/pytest-coverage.txt | awk '$4 != "100%"'
cat .reports/diff-cover-report.md
grep -A5 "<failure" .reports/test-results.xml
```

`.agentignore` excludes `.reports/` but re-includes the two small summary files
on purpose, so a digest is available without the raw dumps.

For a failing pipeline, fetch the answer instead of reproducing it:

```bash
gh run view --log-failed
gh run download <run-id> --name pytest-artifacts --dir .reports-ci
```

Details, including how to compare benchmark runs and extract hot lines from a
Scalene profile, are in
[docs/common_workflows/ci_feedback.md](docs/common_workflows/ci_feedback.md).

______________________________________________________________________

## 11. Reporting back

- State which checks you actually ran, and paste real failure output rather than
  summarising it.
- If `prek` could not run (offline, missing toolchain), say so explicitly instead
  of implying a clean pass.
- If you skipped hooks with `SKIP=` or `--skip`, name them.
- Never claim a commit succeeded without confirming via `git log -1 --oneline`.
- If you did not run the expensive analysis in [§10](#10-reading-ci--analysis-feedback),
  do not describe its results.
