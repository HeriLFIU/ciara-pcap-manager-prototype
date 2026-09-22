"""Object factories shared by the test suite."""

from ciara_pcap_manager_prototype.domain.flows import ExpirationReason, Flow


def make_flow(**overrides: object) -> Flow:
    """
    Build a Flow with sensible defaults, overriding named fields.

    Args:
        **overrides: Field values replacing the defaults.

    Returns:
        The constructed flow.

    """
    base: dict[str, object] = {
        "flow_id": 0,
        "expiration_reason": ExpirationReason.IDLE_TIMEOUT,
        "src_ip": "10.0.0.1",
        "src_port": 5001,
        "dst_ip": "93.184.216.34",
        "dst_port": 80,
        "protocol": 6,
        "protocol_name": "TCP",
        "ip_version": 4,
        "vlan_id": 0,
        "first_seen_ms": 1_700_000_000_000,
        "last_seen_ms": 1_700_000_000_070,
        "duration_ms": 70,
        "bidirectional_packets": 8,
        "bidirectional_bytes": 509,
        "src2dst_packets": 5,
        "src2dst_bytes": 307,
        "dst2src_packets": 3,
        "dst2src_bytes": 202,
        "application_name": "HTTP",
        "application_category_name": "Web",
        "application_is_guessed": False,
        "application_confidence": 6,
    }
    return Flow.model_validate(base | overrides)
