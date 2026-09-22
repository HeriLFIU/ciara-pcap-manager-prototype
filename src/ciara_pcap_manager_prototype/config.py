"""
Configuration shared by every process that touches captures.

Settings are read from the environment (and an optional ``.env``) with the
``CIARA_PCAP_`` prefix, so the API, a CLI invocation and a future worker fleet
can all be pointed at the same storage without code changes.
"""

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class CoreSettings(BaseSettings):
    """Settings for capture storage and flow extraction."""

    model_config = SettingsConfigDict(
        env_prefix="CIARA_PCAP_",
        env_file=".env",
        env_ignore_empty=True,
        extra="ignore",
    )

    storage_dir: Path = Field(
        default=Path(".data/captures"),
        description="Directory that uploaded captures are streamed into.",
    )
    max_upload_bytes: int = Field(
        default=2 * 1024 * 1024 * 1024,
        description="Reject uploads larger than this. Defaults to 2 GiB.",
    )
    upload_chunk_bytes: int = Field(
        default=1024 * 1024,
        description="Chunk size used while streaming an upload to disk.",
    )
    extraction_workers: int = Field(
        default=2,
        ge=1,
        description="Worker processes available for concurrent extractions.",
    )
    n_dissections: int = Field(
        default=20,
        ge=0,
        description="Packets per flow handed to nDPI. Zero disables it.",
    )
    max_flows_per_capture: int = Field(
        default=0,
        ge=0,
        description="Cap on flows extracted per capture. Zero means no limit.",
    )
    extraction_timeout_seconds: float = Field(
        default=300.0,
        gt=0,
        description="Kill an extraction worker that has not finished in this long.",
    )

    def ensure_storage_dir(self) -> Path:
        """
        Create the capture storage directory if it does not exist.

        Returns:
            The resolved storage directory.

        """
        resolved = self.storage_dir.expanduser().resolve()
        resolved.mkdir(parents=True, exist_ok=True)
        return resolved
