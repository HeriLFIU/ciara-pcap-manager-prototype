from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.decode_report import DecodeReport
    from ..models.flow_summary_flows_by_protocol import FlowSummaryFlowsByProtocol
    from ..models.flow_summary_flows_by_termination import FlowSummaryFlowsByTermination


T = TypeVar("T", bound="FlowSummary")


@_attrs_define
class FlowSummary:
    """Aggregate statistics describing an analysed capture."""

    byte_count: int
    """ Inner bytes across every flow. """
    decode: DecodeReport
    """ What the decoder made of every frame in a capture. """
    flow_count: int
    """ Number of flow segments. """
    packet_count: int
    """ Inner packets across every flow. """
    first_seen: float | None | Unset = UNSET
    """ Epoch seconds of the earliest flow start. """
    flows_by_protocol: FlowSummaryFlowsByProtocol | Unset = UNSET
    """ Flow count per protocol name. """
    flows_by_termination: FlowSummaryFlowsByTermination | Unset = UNSET
    """ Flow count per termination reason. """
    last_seen: float | None | Unset = UNSET
    """ Epoch seconds of the latest flow end. """
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        byte_count = self.byte_count

        decode = self.decode.to_dict()

        flow_count = self.flow_count

        packet_count = self.packet_count

        first_seen: float | None | Unset
        if isinstance(self.first_seen, Unset):
            first_seen = UNSET
        else:
            first_seen = self.first_seen

        flows_by_protocol: dict[str, Any] | Unset = UNSET
        if not isinstance(self.flows_by_protocol, Unset):
            flows_by_protocol = self.flows_by_protocol.to_dict()

        flows_by_termination: dict[str, Any] | Unset = UNSET
        if not isinstance(self.flows_by_termination, Unset):
            flows_by_termination = self.flows_by_termination.to_dict()

        last_seen: float | None | Unset
        if isinstance(self.last_seen, Unset):
            last_seen = UNSET
        else:
            last_seen = self.last_seen

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "byte_count": byte_count,
                "decode": decode,
                "flow_count": flow_count,
                "packet_count": packet_count,
            }
        )
        if first_seen is not UNSET:
            field_dict["first_seen"] = first_seen
        if flows_by_protocol is not UNSET:
            field_dict["flows_by_protocol"] = flows_by_protocol
        if flows_by_termination is not UNSET:
            field_dict["flows_by_termination"] = flows_by_termination
        if last_seen is not UNSET:
            field_dict["last_seen"] = last_seen

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.decode_report import DecodeReport  # noqa: PLC0415
        from ..models.flow_summary_flows_by_protocol import FlowSummaryFlowsByProtocol  # noqa: PLC0415
        from ..models.flow_summary_flows_by_termination import FlowSummaryFlowsByTermination  # noqa: PLC0415

        d = dict(src_dict)
        byte_count = d.pop("byte_count")

        decode = DecodeReport.from_dict(d.pop("decode"))

        flow_count = d.pop("flow_count")

        packet_count = d.pop("packet_count")

        def _parse_first_seen(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        first_seen = _parse_first_seen(d.pop("first_seen", UNSET))

        _flows_by_protocol = d.pop("flows_by_protocol", UNSET)
        flows_by_protocol: FlowSummaryFlowsByProtocol | Unset
        if isinstance(_flows_by_protocol, Unset):
            flows_by_protocol = UNSET
        else:
            flows_by_protocol = FlowSummaryFlowsByProtocol.from_dict(_flows_by_protocol)

        _flows_by_termination = d.pop("flows_by_termination", UNSET)
        flows_by_termination: FlowSummaryFlowsByTermination | Unset
        if isinstance(_flows_by_termination, Unset):
            flows_by_termination = UNSET
        else:
            flows_by_termination = FlowSummaryFlowsByTermination.from_dict(_flows_by_termination)

        def _parse_last_seen(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        last_seen = _parse_last_seen(d.pop("last_seen", UNSET))

        flow_summary = cls(
            byte_count=byte_count,
            decode=decode,
            flow_count=flow_count,
            packet_count=packet_count,
            first_seen=first_seen,
            flows_by_protocol=flows_by_protocol,
            flows_by_termination=flows_by_termination,
            last_seen=last_seen,
        )

        flow_summary.additional_properties = d
        return flow_summary

    @property
    def additional_keys(self) -> list[str]:
        return list(self.additional_properties.keys())

    def __getitem__(self, key: str) -> Any:
        return self.additional_properties[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self.additional_properties[key] = value

    def __delitem__(self, key: str) -> None:
        del self.additional_properties[key]

    def __contains__(self, key: str) -> bool:
        return key in self.additional_properties
