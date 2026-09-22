#!/usr/bin/env bash

# This script verifies that you are at the root of a git repository and it will fail if you are not.

set -euo pipefail

if ! command -v git >/dev/null 2>&1; then
    echo "❌ Error: 'git' is not installed or not in the system PATH." >&2
    exit 1
fi

if ! GIT_ROOT=$(git rev-parse --show-toplevel 2>/dev/null); then
    echo "❌ Error: The current directory is not part of a Git repository." >&2
    exit 1
fi

if [[ $GIT_ROOT != "$PWD" ]]; then
    echo "❌ Error: This script must be executed from the root of the Git repository." >&2
    echo "   Current: $PWD" >&2
    echo "   Root:    $GIT_ROOT" >&2
    exit 1
fi

echo "✅ Verified: Executing from the Git repository root."
