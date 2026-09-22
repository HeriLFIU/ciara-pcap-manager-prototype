from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.flow_summary_top_applications import FlowSummaryTopApplications


T = TypeVar("T", bound="FlowSummary")


@_attrs_define
class FlowSummary:
    """Aggregate statistics describing an analysed capture."""

    byte_count: int
    """ Total bytes across every flow. """
    flow_count: int
    """ Number of bidirectional flows extracted. """
    packet_count: int
    """ Total packets across every flow. """
    first_seen_ms: int | None | Unset = UNSET
    """ Earliest packet timestamp across every flow. """
    last_seen_ms: int | None | Unset = UNSET
    """ Latest packet timestamp across every flow. """
    top_applications: FlowSummaryTopApplications | Unset = UNSET
    """ Flow count per nDPI application, highest first. """
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        byte_count = self.byte_count

        flow_count = self.flow_count

        packet_count = self.packet_count

        first_seen_ms: int | None | Unset
        if isinstance(self.first_seen_ms, Unset):
            first_seen_ms = UNSET
        else:
            first_seen_ms = self.first_seen_ms

        last_seen_ms: int | None | Unset
        if isinstance(self.last_seen_ms, Unset):
            last_seen_ms = UNSET
        else:
            last_seen_ms = self.last_seen_ms

        top_applications: dict[str, Any] | Unset = UNSET
        if not isinstance(self.top_applications, Unset):
            top_applications = self.top_applications.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "byte_count": byte_count,
                "flow_count": flow_count,
                "packet_count": packet_count,
            }
        )
        if first_seen_ms is not UNSET:
            field_dict["first_seen_ms"] = first_seen_ms
        if last_seen_ms is not UNSET:
            field_dict["last_seen_ms"] = last_seen_ms
        if top_applications is not UNSET:
            field_dict["top_applications"] = top_applications

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.flow_summary_top_applications import FlowSummaryTopApplications  # noqa: PLC0415

        d = dict(src_dict)
        byte_count = d.pop("byte_count")

        flow_count = d.pop("flow_count")

        packet_count = d.pop("packet_count")

        def _parse_first_seen_ms(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        first_seen_ms = _parse_first_seen_ms(d.pop("first_seen_ms", UNSET))

        def _parse_last_seen_ms(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        last_seen_ms = _parse_last_seen_ms(d.pop("last_seen_ms", UNSET))

        _top_applications = d.pop("top_applications", UNSET)
        top_applications: FlowSummaryTopApplications | Unset
        if isinstance(_top_applications, Unset):
            top_applications = UNSET
        else:
            top_applications = FlowSummaryTopApplications.from_dict(_top_applications)

        flow_summary = cls(
            byte_count=byte_count,
            flow_count=flow_count,
            packet_count=packet_count,
            first_seen_ms=first_seen_ms,
            last_seen_ms=last_seen_ms,
            top_applications=top_applications,
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
