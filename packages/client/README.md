# ciara-pcap-client

Async helpers over the generated `ciara-pcap-sdk`.

| Module        | Contents                                                                                                                       |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `workflow.py` | The client factory and the upload-then-poll job lifecycle, including flow pagination and error normalisation.                  |
| `format.py`   | Counts, bytes, durations, nanoseconds, timestamps and protocol names, so a flow reads the same in a terminal and in a Qt cell. |
| `export.py`   | CSV of SDK flows in the feature codebook's column order.                                                                       |
| `unset.py`    | Narrowing helpers for the SDK's `UNSET` sentinel.                                                                              |

The CLI and the desktop app both build on this package, so the job lifecycle
and the CSV layout are implemented exactly once. It holds no widgets and no
terminal output.
