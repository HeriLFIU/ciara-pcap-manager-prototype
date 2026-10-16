from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.decode_report_skipped import DecodeReportSkipped


T = TypeVar("T", bound="DecodeReport")


@_attrs_define
class DecodeReport:
    """What the decoder made of every frame in a capture."""

    frames_read: int
    """ Frames read from the capture file. """
    inner_packets: int
    """ Frames whose inner TCP/UDP packet was decoded. """
    packets_late: int
    """ Out-of-order packets that lagged by more than the reorder window and were processed out of time order. """
    packets_out_of_order: int
    """ Decoded packets read with a timestamp earlier than one already read; the reorder buffer puts them back in
    time order. """
    packets_over_flow_cap: int
    """ Decoded packets dropped because they would have opened a flow beyond the configured cap. """
    packets_with_int: int
    """ Decoded packets that also carried an INT header. """
    packets_with_int_hops: int
    """ Decoded packets with at least one INT hop decoded. """
    skipped: DecodeReportSkipped | Unset = UNSET
    """ Frames that yielded no inner packet, per reason. """
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        frames_read = self.frames_read

        inner_packets = self.inner_packets

        packets_late = self.packets_late

        packets_out_of_order = self.packets_out_of_order

        packets_over_flow_cap = self.packets_over_flow_cap

        packets_with_int = self.packets_with_int

        packets_with_int_hops = self.packets_with_int_hops

        skipped: dict[str, Any] | Unset = UNSET
        if not isinstance(self.skipped, Unset):
            skipped = self.skipped.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "frames_read": frames_read,
                "inner_packets": inner_packets,
                "packets_late": packets_late,
                "packets_out_of_order": packets_out_of_order,
                "packets_over_flow_cap": packets_over_flow_cap,
                "packets_with_int": packets_with_int,
                "packets_with_int_hops": packets_with_int_hops,
            }
        )
        if skipped is not UNSET:
            field_dict["skipped"] = skipped

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.decode_report_skipped import DecodeReportSkipped  # noqa: PLC0415

        d = dict(src_dict)
        frames_read = d.pop("frames_read")

        inner_packets = d.pop("inner_packets")

        packets_late = d.pop("packets_late")

        packets_out_of_order = d.pop("packets_out_of_order")

        packets_over_flow_cap = d.pop("packets_over_flow_cap")

        packets_with_int = d.pop("packets_with_int")

        packets_with_int_hops = d.pop("packets_with_int_hops")

        _skipped = d.pop("skipped", UNSET)
        skipped: DecodeReportSkipped | Unset
        if isinstance(_skipped, Unset):
            skipped = UNSET
        else:
            skipped = DecodeReportSkipped.from_dict(_skipped)

        decode_report = cls(
            frames_read=frames_read,
            inner_packets=inner_packets,
            packets_late=packets_late,
            packets_out_of_order=packets_out_of_order,
            packets_over_flow_cap=packets_over_flow_cap,
            packets_with_int=packets_with_int,
            packets_with_int_hops=packets_with_int_hops,
            skipped=skipped,
        )

        decode_report.additional_properties = d
        return decode_report

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
