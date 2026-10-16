"""
Configuration shared by every process that touches captures.

Settings are read from the environment (and an optional ``.env``) with the
``CIARA_PCAP_`` prefix, so the API, a CLI invocation and a future worker fleet
can all be pointed at the same storage without code changes.
"""

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from ciara_pcap_manager_prototype.flows.generator import (
    DEFAULT_ACTIVE_TIMEOUT_SECONDS,
    DEFAULT_IDLE_TIMEOUT_SECONDS,
)
from ciara_pcap_manager_prototype.flows.reorder import DEFAULT_REORDER_WINDOW_SECONDS
from ciara_pcap_manager_prototype.pcap.extractor import ExtractionOptions
from ciara_pcap_manager_prototype.telemetry.decoder import DEFAULT_TELEMETRY_PORT


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
    telemetry_udp_port: int = Field(
        default=DEFAULT_TELEMETRY_PORT,
        ge=1,
        le=65535,
        description="Outer UDP destination port that carries telemetry reports.",
    )
    flow_idle_timeout_seconds: float = Field(
        default=DEFAULT_IDLE_TIMEOUT_SECONDS,
        gt=0,
        description="Close a flow segment after this long without a packet.",
    )
    flow_active_timeout_seconds: float = Field(
        default=DEFAULT_ACTIVE_TIMEOUT_SECONDS,
        gt=0,
        description="Close a flow segment that has lasted longer than this.",
    )
    reorder_window_seconds: float = Field(
        default=DEFAULT_REORDER_WINDOW_SECONDS,
        ge=0,
        description="Capture time to buffer packets for, to restore time order "
        "across interleaved report streams. Zero keeps file order.",
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

    def extraction_options(self) -> ExtractionOptions:
        """
        Collect the settings that change how a capture is decoded.

        Returns:
            The options to hand to the extractor.

        """
        return ExtractionOptions(
            telemetry_port=self.telemetry_udp_port,
            idle_timeout_seconds=self.flow_idle_timeout_seconds,
            active_timeout_seconds=self.flow_active_timeout_seconds,
            reorder_window_seconds=self.reorder_window_seconds,
            max_flows=self.max_flows_per_capture,
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
