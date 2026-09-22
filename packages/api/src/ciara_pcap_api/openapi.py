"""
Export the OpenAPI document without starting a server.

The SDK is generated from this file. Dumping the schema from the application
object rather than scraping a running server keeps SDK generation hermetic: no
port to bind, no startup race, and it works unchanged in CI.
"""

import argparse
import json
from pathlib import Path
from typing import Any, cast

from ciara_pcap_api.main import create_app

DEFAULT_OUTPUT = Path("openapi.json")

_OCTET_STREAM = "application/octet-stream"


def _normalize_binary_strings(node: Any) -> None:  # noqa: ANN401 - raw JSON tree
    """
    Rewrite OpenAPI 3.1 binary payloads into the 3.0 spelling, in place.

    OpenAPI 3.1 describes an uploaded file as ``{"type": "string",
    "contentMediaType": "application/octet-stream"}``, which is what Pydantic
    v2 and FastAPI correctly emit. ``openapi-python-client`` 0.29 only
    recognises the 3.0 spelling, ``{"type": "string", "format": "binary"}``,
    and silently generates a ``str`` field that would upload the *file name* as
    a text form field instead of the file's bytes.

    Applying this only to the copy handed to the generator keeps the published
    contract standards-correct.

    Args:
        node: A node of the OpenAPI document tree.

    """
    if isinstance(node, dict):
        typed = cast("dict[str, Any]", node)
        if typed.get("type") == "string" and typed.pop("contentMediaType", None) == (
            _OCTET_STREAM
        ):
            typed["format"] = "binary"
        for value in typed.values():
            _normalize_binary_strings(value)
    elif isinstance(node, list):
        for value in cast("list[Any]", node):
            _normalize_binary_strings(value)


def build_document(*, for_codegen: bool = False) -> dict[str, Any]:
    """
    Produce the application's OpenAPI 3.1 document.

    Args:
        for_codegen: Apply the binary-payload shim that
            ``openapi-python-client`` needs. Never set this for the document
            published to consumers.

    Returns:
        The OpenAPI document.

    """
    document = create_app().openapi()
    if for_codegen:
        _normalize_binary_strings(document)
    return document


def export(output: Path = DEFAULT_OUTPUT, *, for_codegen: bool = False) -> Path:
    """
    Write the application's OpenAPI 3.1 document to disk.

    Args:
        output: Destination path for the JSON document.
        for_codegen: Apply the binary-payload shim before writing.

    Returns:
        The path that was written.

    """
    output.parent.mkdir(parents=True, exist_ok=True)
    # newline="\n" rather than the platform default: the committed contract has
    # to be byte-identical whoever regenerates it, or every export on Windows
    # lands as a whole-file diff and hides the real contract change.
    output.write_text(
        json.dumps(build_document(for_codegen=for_codegen), indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return output


def main() -> None:
    """Run the exporter as a command line program."""
    parser = argparse.ArgumentParser(description="Export the OpenAPI document.")
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Where to write the OpenAPI document.",
    )
    parser.add_argument(
        "--for-codegen",
        action="store_true",
        help="Apply the binary-payload shim required by openapi-python-client.",
    )
    args = parser.parse_args()
    written = export(args.output, for_codegen=bool(args.for_codegen))
    # The path is this program's output; a logger would hide it from a pipeline.
    print(written)  # noqa: T201


if __name__ == "__main__":
    main()
