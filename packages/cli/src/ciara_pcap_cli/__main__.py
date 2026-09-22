"""Command line entry point."""

from ciara_pcap_cli.app import app


def main() -> None:
    """Run the Typer application."""
    app()


if __name__ == "__main__":
    main()
