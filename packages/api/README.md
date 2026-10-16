# ciara-pcap-api

FastAPI backend. An upload is streamed to disk and answered at once with
`202 Accepted` and a job id; the capture is then decoded in an isolated,
time-limited worker process, and the flows of its inner packets are served in
pages.

```bash
uv run ciara-pcap-api        # equivalently: uv run python -m ciara_pcap_api
uv run ciara-pcap-openapi    # dump the OpenAPI document
```

| Path                   | Contents                                                                     |
| ---------------------- | ---------------------------------------------------------------------------- |
| `api/routes/`          | One module per resource. Path operations only.                               |
| `api/main.py`          | Aggregates the route modules into one `api_router`.                          |
| `api/deps.py`          | `AnalysisServiceDep`, the only route access to `app.state`.                  |
| `core/`                | Settings and streaming capture storage.                                      |
| `services/analysis.py` | Job orchestration: store the upload, schedule the parse, record the outcome. |
| `main.py`              | `create_app()` plus the lifespan that builds the collaborators.              |
