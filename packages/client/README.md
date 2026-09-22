# ciara-pcap-client

Async helpers over the generated `ciara-pcap-sdk`.

| Module        | Contents                                                                                                      |
| ------------- | ------------------------------------------------------------------------------------------------------------- |
| `workflow.py` | The client factory and the upload-then-poll job lifecycle, including flow pagination and error normalisation. |
| `format.py`   | Byte, timestamp and nDPI-label formatting, shared so a flow reads the same in a terminal and in a Qt cell.    |
| `unset.py`    | Narrowing helpers for the SDK's `UNSET` sentinel.                                                             |

The CLI and the desktop GUI both build on this package, so the job lifecycle is
implemented exactly once. It holds no widgets and no terminal output.
