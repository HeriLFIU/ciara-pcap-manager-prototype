#!/usr/bin/env bash

set -euo pipefail

HOOKS_DIR=".git/hooks"
NEW_SHEBANG="#!/usr/bin/env -S uv run python"

if [ ! -d "$HOOKS_DIR" ]; then
    echo "❌ Error: .git/hooks directory not found."
    echo "Please run this script from the root of your Git repository."
    exit 1
fi

# Function to safely update the shebang across Linux/macOS
update_shebang() {
    local file=$1
    if sed --version >/dev/null 2>&1; then
        sed -i "1s|.*|$NEW_SHEBANG|" "$file"
    else
        sed -i '' "1s|.*|$NEW_SHEBANG|" "$file"
    fi
}

echo "📥 Downloading Commitizen prepare-commit-msg hook..."
curl -fsSL -o "$HOOKS_DIR/prepare-commit-msg" https://raw.githubusercontent.com/commitizen-tools/commitizen/master/hooks/prepare-commit-msg.py
update_shebang "$HOOKS_DIR/prepare-commit-msg"
chmod +x "$HOOKS_DIR/prepare-commit-msg"

echo "📥 Downloading Commitizen post-commit hook..."
curl -fsSL -o "$HOOKS_DIR/post-commit" https://raw.githubusercontent.com/commitizen-tools/commitizen/master/hooks/post-commit.py
update_shebang "$HOOKS_DIR/post-commit"
chmod +x "$HOOKS_DIR/post-commit"

echo "✅ Commitizen interactive hooks successfully installed and configured for uv!"
