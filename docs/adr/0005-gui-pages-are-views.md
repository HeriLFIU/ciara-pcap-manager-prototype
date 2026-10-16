# 0005. Desktop pages are views; the window is the controller

- Status: Accepted
- Date: 2026-10-15

## Context

The first desktop client was a single window class. The redesign adds an
overview, a flow browser with a detail panel, and a history page, and is
expected to grow.

## Decision

- `AnalysisState` holds the loaded job and flows and emits `analysis_changed`.
- Each page subclasses `Page`, renders from the state in `refresh()`, and
  emits signals for anything that needs the backend or the file system. Pages
  make no network calls.
- `MainWindow` owns all side effects (HTTP through `ciara_pcap_client`, file
  dialogs, CSV export, settings) and builds the sidebar from the `PAGES`
  registry.
- All colours live in `theme.py` as design tokens; widgets select styles by
  object name.

## Consequences

- A new page is one class plus one line in `PAGES`.
- Pages are tested without a server by loading state directly; the window's
  workflows are tested with the client helpers replaced.
- Restyling or adding a theme is a change to one file.
