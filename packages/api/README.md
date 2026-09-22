# ciara-pcap-api

FastAPI backend. Uploads are streamed to disk and parsed by NFStream in an
isolated worker process; the route returns `202 Accepted` with a job id.

```bash
uv run ciara-pcap-api        # equivalently: uv run python -m ciara_pcap_api
uv run ciara-pcap-openapi    # dump the OpenAPI document
```

Use those entry points, not `uvicorn` directly: they prepare the packet-capture
backend before any worker process is spawned, which `uvicorn` on its own does
not do, and the engine then fails to load on Windows hosts still carrying a
legacy WinPcap installation.

| Path                   | Contents                                                                     |
| ---------------------- | ---------------------------------------------------------------------------- |
| `api/routes/`          | One module per resource. Path operations only.                               |
| `api/main.py`          | Aggregates the route modules into one `api_router`.                          |
| `api/deps.py`          | `AnalysisServiceDep`, the only route access to `app.state`.                  |
| `core/`                | Settings and streaming capture storage.                                      |
| `services/analysis.py` | Job orchestration: store the upload, schedule the parse, record the outcome. |
| `main.py`              | `create_app()` plus the lifespan that builds the collaborators.              |
