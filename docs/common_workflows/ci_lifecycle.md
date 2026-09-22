# 🔄 The CI Pipeline Lifecycle

The Continuous Integration pipeline was designed to be very efficient. When a developer opens a Pull Request or pushes to the `main` branch, GitHub Actions executes the following jobs:

### 1. Code Quality Gate (`prek-checks`)

Before any of the tests, the pipeline runs all of the `prek` hooks within the configuration file. It caches the environment so that it does not have to set everything up again. It also specifically targets files modified in the PR to enforce formatting, linting, type-checking, security scans, and anything else you want. If this job fails, the rest of the pipeline is aborted to save on minutes.

### 2. Full Tests & Coverage (`comprehensive-tests`)

Once code quality is validated, the pipeline parallelizes the Pytest test suite across all available CPU cores using `pytest-xdist`. It generates XML coverage reports. It also runs `diff-cover` to analyze the PR. `diff-cover` ensures that **only new code** meets the coverage threshold needed for the job to pass. The threshold is currently **50%**, and it is set in `.github/workflows/ci.yml`.

### 3. Performance Benchmarks (`performance-benchmarks`)

To prevent performance regressions, this job intentionally disables parallelization (`-n 0`). It runs isolated micro-benchmarks (via `pytest-benchmark`).

### 4. Scalene Profiler (`profiling`)

Finally, the pipeline executes the Scalene profiler against the application entry point. It monitors CPU, GPU, and memory usage. It can also output its report files via the GitHub Actions artifact summary for developers to view.

### Reading the results

Every job uploads its `.reports/` directory as an artifact, and the diff-coverage summary is written into the job summary. See [Reading CI & Profiler Feedback](ci_feedback.md) for how to pull those down and what each file answers.
