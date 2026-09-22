# ==============================================================================
# Configuration
# ==============================================================================

# Enforce bash with strict error handling (-e exits on error, -u errors on undefined variables)
SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

# Ensure that when you run "make" without any arguments it displays the help menu
.DEFAULT_GOAL := help

.PHONY: help all clean test setup profile profile-export lint format typecheck lock update-hooks bench report analyze

# ==============================================================================
# Development Workflow
# ==============================================================================

help: ## Display help menu
	@echo "Usage: make [target]"
	@echo ""
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

all: setup ## Run initial setup

setup: ## Hydrate environment and install all git hooks (MOST IMPORTANT!) (ALWAYS USE AT START WHEN FRESHLY CLONED!)
	./scripts/non-interactive/is-git-project-root.sh
	uv sync
	./scripts/non-interactive/install-deps.sh
	./scripts/non-interactive/setup-prek.sh
	./scripts/non-interactive/install-commitizen-hooks.sh

clean: ## Wipe temporary files, caches, and test artifacts
	@echo "🧹 Cleaning up repository caches..."
	@rm -rf .reports/ .pytest_cache/ .ruff_cache/ .benchmarks/
	@find . -type d -name "__pycache__" -exec rm -rf {} +
	@echo "✨ Clean complete."

# ==============================================================================
# Testing & Profiling
# ==============================================================================

test: ## Execute the full test suite
	uv run pytest tests

profile: ## Run Scalene profiler locally and open the Web UI
	@echo "🔍 Launching Scalene Profiler on the application entry point..."
	uv run scalene run \
		--profile-all \
		--reduced-profile \
		src/ciara_pcap_manager_prototype/main.py

profile-export: ## Export Scalene profile as static HTML (This is broken)
	@echo "💾 Exporting Scalene profile to .reports/..."
	@mkdir -p .reports
	uv run scalene run --outfile .reports/scalene-profile.json src/ciara_pcap_manager_prototype/main.py
	uv run scalene view --standalone .reports/scalene-profile.json
	mv scalene-profile.html .reports/scalene-profile.html

# ==============================================================================
# Code Quality & Tooling
# ==============================================================================

lint: ## Run the entire quality check pipeline (Ruff, Pyright, Codespell, Shellcheck)
	@echo "🧹 Running PreK hooks across all files..."
	uv run prek run --all-files

format: ## Fast auto-format using Ruff locally instead of with Prek
	@echo "✨ Auto-formatting Python code..."
	uv run ruff check --fix .
	uv run ruff format .

typecheck: ## Run strict static type checking in isolation
	@echo "🔍 Running Pyright in strict mode..."
	uv run pyright

lock: ## Resolve dependencies and update the uv.lock file
	@echo "🔒 Updating uv.lock..."
	uv lock

update-hooks: ## Update all Prek hooks to the latest version
	@echo "⬆️ Updating PreK hook versions..."
	uv run prek autoupdate

# ==============================================================================
# Deep Analysis (expensive — run deliberately, not on every change)
# ==============================================================================
#
# These targets exist so that a human *or an AI coding agent* can read concrete
# measurements instead of guessing. They are slow and they burn CPU, so they are
# deliberately not wired into `lint` or the commit hooks. Run them before a
# release, when a change is performance-sensitive, or when something is asked
# of you that needs evidence.
#
# Everything lands in .reports/. See docs/common_workflows/ci_feedback.md for
# which file answers which question.

bench: ## Run micro-benchmarks only, serially, and record them as JSON
	@mkdir -p .reports
	uv run pytest tests -n 0 --benchmark-enable --benchmark-only --benchmark-json=.reports/benchmark.json

report: ## Run the full suite and write machine-readable reports into .reports/
	@mkdir -p .reports
	uv run pytest tests --cov-report=xml:.reports/coverage.xml --junitxml=.reports/test-results.xml | tee .reports/pytest-coverage.txt

analyze: report bench ## Everything in `report`, plus benchmarks — the full local evidence pass
	@echo "📊 Reports written to .reports/. See docs/common_workflows/ci_feedback.md."
