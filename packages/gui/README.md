# ciara-pcap-gui

The PySide6 desktop app.

```bash
uv run ciara-pcap-gui
```

Open a capture (button, Ctrl+O, or drag and drop). The **Overview** page shows
headline numbers and breakdowns, **Flows** lists every flow segment with a
filter and a panel showing all 99 codebook features of the selected flow, and
**History** reopens earlier analyses. Flows export to CSV in codebook order.
Light and dark themes. A tour with screenshots is in
[docs/user-guide.md](../../docs/user-guide.md).

The upload, the polling and the paging are coroutines driven by `qasync`,
which runs asyncio on the Qt event loop, so the window stays interactive with
no worker threads.

The flow table sorts and filters in Python rather than through
`QSortFilterProxyModel`, which calls back into Python for both cells of every
comparison: `FlowFilterProxy` sorts once with `sorted` over cached keys and
filters with one pass over precomputed search text. On the 50,000-frame
sample (15,458 flows) a sort takes about 10 ms instead of 0.6–0.9 s.

| Module           | Role                                                         |
| ---------------- | ------------------------------------------------------------ |
| `main_window.py` | shell and controller: every network call, dialog and setting |
| `state.py`       | the loaded analysis, shared by the pages                     |
| `pages/`         | one view per sidebar entry; register new ones in `PAGES`     |
| `widgets/`       | cards, breakdown bars, pills, drop zone, flow detail panel   |
| `theme.py`       | colour tokens and the generated stylesheet                   |
| `tones.py`       | which colour a protocol, termination or job status gets      |
| `models.py`      | Qt table models with declarative columns; the flow proxy     |
