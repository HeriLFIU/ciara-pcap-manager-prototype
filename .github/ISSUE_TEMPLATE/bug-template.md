---
name: Bug Report
about: Report a malfunction or regression.
title: 'fix(<scope>): <short_description>'
labels: [bug, high-priority]
assignees: ''
---

## Problem Description

Clear and concise description of the failure.

## Evidence & Logs

Paste relevant logs from Zabbix, Grafana, or the VM console.

## Reproduction (Red Phase)

_To obey the testing goat, you must provide a failing test case._

- [ ] **Failing Test Command:** (e.g., `pytest tests/test_bug.py`)
- [ ] **Expected Behavior:** What should have happened?
- [ ] **Actual Behavior:** What happened instead?

## Technical Environment

- **Platform:** (e.g., NocoBase, Kytos, Zabbix)
- **Commit Hash:** [Insert hash where bug occurs]

## Resolution Criteria

- [ ] Bug is resolved.
- [ ] Regression test is added to the permanent test suite.
- [ ] Verified against the [Application Plane Constitution](./constitution.md).
