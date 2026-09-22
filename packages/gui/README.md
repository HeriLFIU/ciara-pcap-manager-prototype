# ciara-pcap-gui

The PySide6 desktop client.

```bash
uv run ciara-pcap-gui
```

Choose **File → Open capture…**, pick a `.pcap`, and the extracted flows appear
in a sortable, filterable table.

The upload, the job polling and the flow paging are coroutines driven by
`qasync`, which runs asyncio on the Qt event loop. The window keeps repainting
and stays interactive for the whole request — no worker threads and no
cross-thread signal marshalling.
