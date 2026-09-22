#!/usr/bin/env bash

# Installs OS-level tooling that is convenient to have on the PATH directly.
# The prek hooks bring their own pinned copies of these tools, so this script is
# best-effort: unsupported platforms are skipped with a note instead of failing
# the whole `make setup` run.

set -euo pipefail

if command -v shellcheck >/dev/null 2>&1; then
    echo "✅ shellcheck is already installed; nothing to do."
    exit 0
fi

install_with_sudo() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        echo "⚠️  Neither root nor sudo is available; skipping shellcheck install." >&2
        exit 0
    fi
}

case "$(uname -s)" in
Linux*)
    if command -v apt-get >/dev/null 2>&1; then
        install_with_sudo apt-get update -qq
        install_with_sudo apt-get install -y shellcheck
    elif command -v dnf >/dev/null 2>&1; then
        install_with_sudo dnf install -y ShellCheck
    elif command -v pacman >/dev/null 2>&1; then
        install_with_sudo pacman -S --noconfirm shellcheck
    elif command -v apk >/dev/null 2>&1; then
        install_with_sudo apk add --no-cache shellcheck
    else
        echo "⚠️  No supported package manager found; skipping shellcheck install."
    fi
    ;;
Darwin*)
    if command -v brew >/dev/null 2>&1; then
        brew install shellcheck
    else
        echo "⚠️  Homebrew not found; skipping shellcheck install."
    fi
    ;;
MINGW* | MSYS* | CYGWIN*)
    # Windows: the shellcheck-py prek hook ships its own binary, so a system
    # install is optional. Try the usual Windows package managers, then move on.
    if command -v scoop >/dev/null 2>&1; then
        scoop install shellcheck
    elif command -v choco >/dev/null 2>&1; then
        choco install shellcheck -y
    else
        echo "ℹ️  Windows detected without scoop/choco; skipping shellcheck install."
        echo "   The prek hooks provide their own shellcheck, so this is optional."
    fi
    ;;
*)
    echo "ℹ️  Unrecognized platform '$(uname -s)'; skipping shellcheck install."
    ;;
esac
