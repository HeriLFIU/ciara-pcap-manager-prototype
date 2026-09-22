# ciara-pcap-cli

The `ciara-pcap` command line interface.

```bash
uv run ciara-pcap health              # is the backend reachable?
uv run ciara-pcap analyze x.pcap      # upload, wait, print a flow table
uv run ciara-pcap analyze x.pcap --json
uv run ciara-pcap jobs                # list analysis jobs
uv run ciara-pcap flows <job-id>      # re-read a finished job
```

Point it at a backend with `--api-url` or `CIARA_PCAP_API_URL`.

Every network call goes through the generated SDK, so a backend contract change
breaks this package at type-check time rather than at run time.
