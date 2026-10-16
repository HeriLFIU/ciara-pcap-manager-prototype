"""Server entry point."""


def main() -> None:
    """Serve the API with uvicorn using the configured host and port."""
    import uvicorn  # noqa: PLC0415 - keep server import out of the spawn path

    from ciara_pcap_api.core.config import get_settings  # noqa: PLC0415 - same

    settings = get_settings()
    uvicorn.run(
        "ciara_pcap_api.main:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level,
    )


if __name__ == "__main__":
    main()
