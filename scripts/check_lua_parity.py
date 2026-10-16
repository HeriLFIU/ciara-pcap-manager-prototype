"""
Compare the Python decoder with the Wireshark Lua dissector, frame by frame.

``scripts/non-interactive/check-lua-parity.sh`` runs tshark with
``tools/wireshark/int_extension_fullframe_v7.lua`` and writes one TSV row per
frame; this program decodes the same capture with
:func:`ciara_pcap_manager_prototype.telemetry.decoder.decode_frame` and checks
that every field agrees. It exits non-zero on the first kind of disagreement
and prints up to five examples.

Usage::

    uv run python scripts/check_lua_parity.py --fields
    uv run python scripts/check_lua_parity.py capture.pcap tshark-fields.tsv
"""

import argparse
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from ciara_pcap_manager_prototype.pcap.reader import iter_frames
from ciara_pcap_manager_prototype.telemetry.decoder import IP_PROTO_TCP, decode_frame
from ciara_pcap_manager_prototype.telemetry.layers import DecodedPacket

if TYPE_CHECKING:
    from collections.abc import Iterable

#: The tshark fields the shell script extracts, in column order. Fields that
#: occur more than once (outer and inner IPv4, several hops) are joined by ";".
TSHARK_FIELDS = (
    "frame.number",
    "telemetry.f_report_header.f_switch_id",
    "telemetry.f_report_header.f_seq_num",
    "int_shim.shim_header.shim_len",
    "int_metadata.int_metadata_header.int_ml",
    "int_stack.int_switch_id",
    "int_stack.int_ingress_egress_ports.int_ingress_port",
    "int_stack.int_ingress_egress_ports.int_egress_port",
    "int_stack.int_queue_id_and_occ.int_queue_occ",
    "int_stack.int_ingress_ts",
    "int_stack.int_egress_ts",
    "int_stack.int_hop_latency",
    "ip.src",
    "ip.dst",
    "ip.proto",
    "ip.len",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.flags",
    "udp.srcport",
    "udp.dstport",
    "vlan.id",
)


def _join(values: "Iterable[object]") -> str:
    """
    Join several occurrences of a field the way tshark does.

    Args:
        values: The field values, in packet order.

    Returns:
        The values separated by ``;``.

    """
    return ";".join(str(value) for value in values)


def expected_row(index: int, packet: DecodedPacket) -> list[str]:
    """
    Render the decoder's view of a frame in tshark's field formats.

    Args:
        index: Zero-based frame index.
        packet: The decoded frame.

    Returns:
        One value per entry of `TSHARK_FIELDS`.

    """
    telemetry = packet.int_telemetry
    hops = telemetry.hops if telemetry is not None else ()
    return [
        str(index + 1),
        f"0x{packet.report.switch_id:08x}",
        f"0x{packet.report.sequence_number:08x}",
        "" if telemetry is None else str(telemetry.shim.length_words),
        "" if telemetry is None else str(telemetry.metadata.hop_ml_words),
        _join(f"0x{hop.switch_id:08x}" for hop in hops if hop.switch_id is not None),
        _join(hop.ingress_port for hop in hops if hop.ingress_port is not None),
        _join(hop.egress_port for hop in hops if hop.egress_port is not None),
        _join(hop.queue_occupancy for hop in hops if hop.queue_occupancy is not None),
        _join(
            hop.ingress_timestamp for hop in hops if hop.ingress_timestamp is not None
        ),
        _join(hop.egress_timestamp for hop in hops if hop.egress_timestamp is not None),
        _join(hop.hop_latency for hop in hops if hop.hop_latency is not None),
        f"{packet.outer.src_ip};{packet.inner.src_ip}",
        f"{packet.outer.dst_ip};{packet.inner.dst_ip}",
        f"17;{packet.inner.ip_proto}",
        str(packet.inner.ip_total_length),
        *_l4_fields(packet),
        _join((*packet.outer.vlan_ids, *packet.inner.vlan_ids)),
    ]


def _l4_fields(packet: DecodedPacket) -> list[str]:
    """
    Render the inner L4 fields as tshark reports them.

    tshark decodes the outer UDP header too, so UDP fields list the outer
    value first and, for an inner UDP packet, the inner value second.

    Args:
        packet: The decoded frame.

    Returns:
        tcp.srcport, tcp.dstport, tcp.flags, udp.srcport and udp.dstport.

    """
    inner, outer = packet.inner, packet.outer
    if inner.ip_proto == IP_PROTO_TCP:
        return [
            str(inner.src_port),
            str(inner.dst_port),
            f"0x{inner.tcp_flags:04x}",
            str(outer.src_port),
            str(outer.dst_port),
        ]
    return [
        "",
        "",
        "",
        f"{outer.src_port};{inner.src_port}",
        f"{outer.dst_port};{inner.dst_port}",
    ]


def compare(capture: Path, tsv: Path) -> int:
    """
    Compare every frame and report disagreements.

    Args:
        capture: The capture tshark read.
        tsv: tshark's field output for it.

    Returns:
        The number of frames that disagree.

    """
    rows = tsv.read_text(encoding="utf-8").splitlines()
    frames = list(iter_frames(capture))
    if len(rows) != len(frames):
        sys.stdout.write(f"tshark wrote {len(rows)} rows for {len(frames)} frames\n")
        return max(len(rows), len(frames))

    mismatches = 0
    for frame, row in zip(frames, rows, strict=True):
        decoded = decode_frame(frame.data)
        actual = row.split("\t")
        if not isinstance(decoded, DecodedPacket):
            # The Lua adds nothing for a frame it cannot decode either.
            if any(actual[1:12]):
                mismatches += 1
            continue
        expected = expected_row(frame.index, decoded)
        # tshark reports ip.len for both IPv4 headers; compare the inner one.
        ip_len = TSHARK_FIELDS.index("ip.len")
        actual[ip_len] = actual[ip_len].split(";")[-1]
        if actual != expected:
            mismatches += 1
            if mismatches <= 5:  # noqa: PLR2004 - examples to print
                sys.stdout.write(
                    f"frame {frame.index + 1}\n"
                    f"  lua:    {actual}\n"
                    f"  python: {expected}\n"
                )

    fields = len(frames) * len(TSHARK_FIELDS)
    sys.stdout.write(
        f"compared {len(frames)} frames ({fields} fields): {mismatches} disagree\n"
    )
    return mismatches


def main() -> int:
    """
    Run the comparison from the command line.

    Returns:
        0 when every frame agrees, 1 otherwise.

    """
    parser = argparse.ArgumentParser(description="Compare the decoder with the Lua.")
    parser.add_argument("capture", type=Path, nargs="?")
    parser.add_argument("tsv", type=Path, nargs="?")
    parser.add_argument(
        "--fields", action="store_true", help="Print the tshark fields to extract."
    )
    args = parser.parse_args()
    if args.fields:
        sys.stdout.write("\n".join(TSHARK_FIELDS) + "\n")
        return 0
    if args.capture is None or args.tsv is None:
        parser.error("capture and tsv are required")
    return 0 if compare(args.capture, args.tsv) == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
