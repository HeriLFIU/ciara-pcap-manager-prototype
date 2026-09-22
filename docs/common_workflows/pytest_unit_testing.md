# 🧪 Pytest Unit Testing & Coverage

We use [pytest](https://docs.pytest.org/) as our testing framework, along with `pytest-xdist` for parallel execution and `pytest-benchmark` for performance tests. All test-related commands can be run via `uv run` or our Makefile.

## Day-to-Day Workflows

### Running the Full Suite

To execute all tests in parallel across available CPUs, run:

```bash
uv run pytest tests/ -n auto
```

This leverages `pytest-xdist` to distribute tests to all CPU cores (the `-n auto` flag does this). We also provide `make test` as a shortcut for the full test suite.

### Running Specific Tests

To run only a specific test file or even a single test function, target it directly. For example:

```bash
uv run pytest tests/unit/test_parser.py
uv run pytest tests/unit/test_parser.py::test_parse_flow_header_snapshot
```

These commands will execute just the given test file or function.

### Generating Coverage Reports

Coverage is already wired into `addopts` in `pyproject.toml` (`--cov=ciara_pcap_manager_prototype`), so a bare run reports it. For an explicit console report:

```bash
uv run pytest tests/ --cov=ciara_pcap_manager_prototype --cov-report=term-missing
```

This will print a coverage summary to the terminal. (In CI, we generate an XML report and use diff-cover to enforce coverage on changed lines, but for day-to-day you can rely on the above.)

### Running Micro-Benchmarks

For performance testing, we use `pytest-benchmark`. Because benchmarks should not run in parallel (they require CPU isolation), we disable xdist with `-n 0`. To run all benchmarks:

```bash
uv run pytest tests/ -n 0 --benchmark-enable --benchmark-only
```

The flags `--benchmark-enable` and `--benchmark-only` ensure that benchmarking is enabled and that only benchmarks (not ordinary tests) run. You can also target a specific benchmark by file or test function similarly to running normal tests.

### Snapshot Tests

`syrupy` stores expected values under `tests/**/__snapshots__/`. When an intentional change makes a snapshot stale, regenerate it rather than editing the `.ambr` file:

```bash
uv run pytest tests --snapshot-update
```

### Network Isolation

`--disable-socket` is applied by default, so tests cannot reach the network. Mock it instead. `tests/conftest.py` relaxes this to loopback-only on Windows, because asyncio needs `socket.socketpair()` there; a test asserting that the network is blocked must therefore accept both failure modes and catch `RuntimeError` rather than a platform-specific subclass.
