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

| Module           | Role                                                         |
| ---------------- | ------------------------------------------------------------ |
| `main_window.py` | shell and controller: every network call, dialog and setting |
| `state.py`       | the loaded analysis, shared by the pages                     |
| `pages/`         | one view per sidebar entry; register new ones in `PAGES`     |
| `widgets/`       | cards, breakdown bars, pills, drop zone, flow detail panel   |
| `theme.py`       | colour tokens and the generated stylesheet                   |
| `tones.py`       | which colour a protocol, termination or job status gets      |
| `models.py`      | Qt table models with declarative columns                     |
