# 🛠️ Development Tools Overview

Our pipeline integrates several bleeding-edge tools to automate code quality, dependency management, and releases.

## UV

`uv` is utilized as the project build backend and frontend. It is an efficient, modern, and automated tool used to manage and build Python projects. It is also faster than `pip`.

## Ruff

Ruff is an extremely fast Python linter and formatter written in Rust. It replaces other tools like (like Flake8, Black, isort, and pyupgrade).

## Prek

`prek` was chosen because it is written in Rust and is significantly more performant than the standard `pre-commit` tool, while remaining completely backwards compatible. The upside of `prek` is its ease of use and minimal setup. Hooks are also very easy to manage and setup.

## Copier

Copier generated this project from a template and keeps it linked to that template through `.copier-answers.yml`. When the template gains a new hook, a CI fix, or a better default, `copier update` replays those changes into this project on top of your own work, instead of you copying files by hand. See [Using and Updating the Copier Template](common_workflows/copier_template.md).

## Scalene

Scalene is a Python profiler for memory, CPU, and GPU.

## Commitizen

Commitizen provides an interactive command-line interface for writing commits, ensuring they follow a proper specification (like Conventional Commits). While it *can* automatically generate changelogs and bump versions, within this project, we rely on Google's `Release Please` for automation and only use Commitizen locally as an interactive CLI to author commits.

## Release Please (Automated version bumping and changelog generation)

Release Please is Google's automated release bot. It functions similarly to Semantic Release, but instead of pushing tags directly to the main branch (which is a security risk), it creates a dedicated Pull Request containing the new changelog and version bump, which you can manually approve and merge.

> **⚠️ IMPORTANT:** To utilize `Release Please` effectively, you **cannot** merge pull requests as you normally would. You must use **Squash and Merge** in GitHub. This keeps the commit history linear, removes messy "work-in-progress" commits, and provides a single, clean commit message that `Release Please` can interpret to bump the version correctly.
