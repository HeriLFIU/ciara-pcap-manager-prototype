# 📊 Reading CI & Profiler Feedback

Most of the checks in this project are cheap, run on every commit, and print
everything you need to the terminal. A few are not: the full test suite with
coverage, the micro-benchmarks, and the Scalene profiler. Those produce
*measurements*, and measurements are worth reading rather than guessing at.

This page is written for both humans and AI coding agents. The point is simple:
when a decision depends on a number — is this slower, is this covered, did this
actually fail — read the artifact instead of assuming.

## When to run the expensive pass

Running the full analysis is slow and, for an agent, expensive in tokens and
time. It is deliberately **not** part of `make lint` or the commit hooks.

Run it when:

- You are preparing a release.
- You changed something on a hot path and are claiming it is faster or no slower.
- Coverage on new code is in question.
- A test failed and the terminal output was truncated or unclear.
- Someone asked you to.

Do **not** run it:

- On every edit, or in a loop.
- To "check nothing broke" when the fast hooks already answered that.
- Before you have made the change you intend to measure.

## Producing the reports

```bash
make report     # full suite: coverage XML, JUnit XML, terminal coverage table
make bench      # micro-benchmarks only, serial, JSON output
make analyze    # everything above, in one go
```

Profiling is separate, because it runs the application rather than the tests:

```bash
uv run scalene run --outfile .reports/scalene-profile.json src/ciara_pcap_manager_prototype/main.py
```

Never run bare `make profile` from an automated context — it opens a browser UI and
does not exit.

## What each artifact answers

Everything lands in `.reports/`, which is gitignored.

| File                            | Answers                                           | Size   |
| ------------------------------- | ------------------------------------------------- | ------ |
| `.reports/pytest-coverage.txt`  | Which lines are uncovered, per file, as a table   | small  |
| `.reports/test-results.xml`     | Which tests failed, with the failure text (JUnit) | medium |
| `.reports/coverage.xml`         | Machine-readable per-line coverage (Cobertura)    | large  |
| `.reports/diff-cover-report.md` | Coverage of **changed lines only**                | small  |
| `.reports/benchmark.json`       | Timing per benchmark: min, mean, stddev, rounds   | large  |
| `.reports/scalene-profile.json` | Line-level CPU, GPU and memory attribution        | large  |
| `.reports/htmlcov/`             | The same coverage, for a human in a browser       | large  |

### Read the small ones first

The two small files answer most questions on their own. Prefer them, and prefer
extracting a few lines over loading a whole file:

```bash
# Which lines are not covered? The column pattern keeps this to real coverage
# rows — a bare `\.py` match also picks up test ids in the warnings summary.
grep -E "^\S+\.py +[0-9]+ +[0-9]+ +[0-9]+%" .reports/pytest-coverage.txt | awk '$4 != "100%"'

# Coverage of the lines this branch actually changed
cat .reports/diff-cover-report.md

# Just the failures, not the whole JUnit file
grep -A5 "<failure" .reports/test-results.xml
```

### Comparing benchmarks

A single benchmark run is a number, not a comparison. To claim a change is
faster, record the baseline first:

```bash
git stash                                   # or check out the base commit
make bench
cp .reports/benchmark.json .reports/benchmark-base.json
git stash pop
make bench
```

Then compare. **Do not read `benchmark.json` directly** — it embeds every raw
timing sample and runs to several megabytes for even one benchmark. Pull out
only the summary statistics:

```bash
uv run python -c "
import json, pathlib, sys
def stats(path):
    data = json.loads(pathlib.Path(path).read_text())
    return {b['fullname']: b['stats'] for b in data['benchmarks']}
base, new = stats('.reports/benchmark-base.json'), stats('.reports/benchmark.json')
for name, s in new.items():
    b = base.get(name)
    if not b:
        continue
    delta = (s['mean'] - b['mean']) / b['mean'] * 100
    noise = (b['stddev'] + s['stddev']) / b['mean'] * 100
    verdict = 'noise' if abs(delta) < noise else ('slower' if delta > 0 else 'FASTER')
    print(f'{name}: {delta:+.1f}% (noise +/-{noise:.1f}%) -> {verdict}')
"
```

A difference smaller than the combined standard deviation is noise — report it
as such rather than claiming an improvement.

pytest-benchmark can also do the comparison itself with `--benchmark-compare`
against a saved run in `.benchmarks/`.

### Reading a Scalene profile

`scalene-profile.json` is large. Do not read it whole. Extract the hot lines:

```bash
uv run python -c "
import json, pathlib
d = json.loads(pathlib.Path('.reports/scalene-profile.json').read_text())
for fname, finfo in d['files'].items():
    for line in finfo['lines']:
        cpu = line['n_cpu_percent_python'] + line['n_cpu_percent_c']
        if cpu > 1.0:
            print(f\"{cpu:6.2f}%  {fname}:{line['lineno']}\")
"
```

Attribute time to *lines*, and quote the line when you report a finding.

## Reading feedback from the remote pipeline

When CI fails on a pull request, the answer is already on GitHub — fetching it
is far cheaper than reproducing the failure locally:

```bash
gh run list --branch "$(git branch --show-current)" --limit 5
gh run view --log-failed              # only the failing steps
gh run view <run-id> --log-failed
```

The pipeline also uploads its `.reports/` directory as an artifact on every run,
and writes the diff-coverage summary into the job summary:

```bash
gh run download <run-id> --name pytest-artifacts --dir .reports-ci
```

## A note on `.agentignore`

`.agentignore` excludes `.reports/` wholesale, because these files are large,
regenerated constantly, and would otherwise flood a search. The small summary
files are re-included explicitly:

```gitignore
.reports/*
!.reports/pytest-coverage.txt
!.reports/diff-cover-report.md
```

That is deliberate — an agent gets the digest without the raw dumps. If you need
one of the large files, read it with a targeted command as shown above rather
than opening it.

## Reporting what you found

- Quote the number and where it came from: file, test name, line.
- If a difference is within noise, say so instead of rounding it into a win.
- If you did not run the analysis, do not describe its results.
