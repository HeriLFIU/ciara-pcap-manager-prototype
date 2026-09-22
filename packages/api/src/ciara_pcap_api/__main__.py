"""
Server entry point.

``ensure_capture_backend`` is called at *module import* time on purpose.
``multiprocessing`` spawns re-import the parent's ``__main__`` module in every
descendant process, which is how NFStream's own metering processes inherit the
packet-capture library search path. Starting uvicorn from its own console
script skips this module, and the engine then fails to load on Windows hosts
that still carry a legacy WinPcap installation.
"""

from ciara_pcap_manager_prototype.pcap.compat import ensure_capture_backend

ensure_capture_backend()


def main() -> None:
    """Serve the API with uvicorn using the configured host and port."""
    import uvicorn  # noqa: PLC0415 - keep server import out of the spawn path

    from ciara_pcap_api.core.config import get_settings  # noqa: PLC0415

    settings = get_settings()
    uvicorn.run(
        "ciara_pcap_api.main:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level,
    )


if __name__ == "__main__":
    main()
