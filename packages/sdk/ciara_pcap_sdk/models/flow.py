from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.expiration_reason import ExpirationReason, check_expiration_reason
from ..types import UNSET, Unset

T = TypeVar("T", bound="Flow")


@_attrs_define
class Flow:
    """A single bidirectional flow extracted from a packet capture."""

    application_category_name: str
    """ nDPI application category. """
    application_confidence: int
    """ nDPI confidence identifier. """
    application_is_guessed: bool
    """ True when nDPI inferred the label instead of dissecting it. """
    application_name: str
    """ nDPI application label, for example `DNS` or `TLS.Google`. """
    bidirectional_bytes: int
    """ Total bytes in both directions. """
    bidirectional_packets: int
    """ Total packets in both directions. """
    dst2src_bytes: int
    """ Bytes sent from destination to source. """
    dst2src_packets: int
    """ Packets sent from destination to source. """
    dst_ip: str
    """ Destination IP address of the first packet seen. """
    dst_port: int
    """ Destination transport port, or 0 when not applicable. """
    duration_ms: int
    """ Wall-clock lifetime of the flow. """
    expiration_reason: ExpirationReason
    """ Why NFStream closed a flow.

    NFStream encodes this as ``expiration_id``: ``0`` for the idle timeout,
    ``1`` for the active timeout and ``-1`` when an ``NFPlugin`` forced a
    custom expiration. """
    first_seen_ms: int
    """ Unix epoch milliseconds of the first packet in either direction. """
    flow_id: int
    """ Per-capture index assigned by NFStream. """
    ip_version: int
    """ IP version, 4 or 6. """
    last_seen_ms: int
    """ Unix epoch milliseconds of the last packet in either direction. """
    protocol: int
    """ IANA IP protocol number. """
    protocol_name: str
    """ Human-readable form of `protocol`. """
    src2dst_bytes: int
    """ Bytes sent from source to destination. """
    src2dst_packets: int
    """ Packets sent from source to destination. """
    src_ip: str
    """ Source IP address of the first packet seen. """
    src_port: int
    """ Source transport port, or 0 when not applicable. """
    vlan_id: int
    """ VLAN identifier, 0 when untagged. """
    client_fingerprint: None | str | Unset = UNSET
    """ JA3/JA4-style client fingerprint, when available. """
    content_type: None | str | Unset = UNSET
    """ Cleartext HTTP content type, when observed. """
    requested_server_name: None | str | Unset = UNSET
    """ TLS SNI or DNS query name, when one was observed. """
    server_fingerprint: None | str | Unset = UNSET
    """ Server-side handshake fingerprint, when available. """
    user_agent: None | str | Unset = UNSET
    """ Cleartext HTTP user agent, when observed. """
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        application_category_name = self.application_category_name

        application_confidence = self.application_confidence

        application_is_guessed = self.application_is_guessed

        application_name = self.application_name

        bidirectional_bytes = self.bidirectional_bytes

        bidirectional_packets = self.bidirectional_packets

        dst2src_bytes = self.dst2src_bytes

        dst2src_packets = self.dst2src_packets

        dst_ip = self.dst_ip

        dst_port = self.dst_port

        duration_ms = self.duration_ms

        expiration_reason: str = self.expiration_reason

        first_seen_ms = self.first_seen_ms

        flow_id = self.flow_id

        ip_version = self.ip_version

        last_seen_ms = self.last_seen_ms

        protocol = self.protocol

        protocol_name = self.protocol_name

        src2dst_bytes = self.src2dst_bytes

        src2dst_packets = self.src2dst_packets

        src_ip = self.src_ip

        src_port = self.src_port

        vlan_id = self.vlan_id

        client_fingerprint: None | str | Unset
        if isinstance(self.client_fingerprint, Unset):
            client_fingerprint = UNSET
        else:
            client_fingerprint = self.client_fingerprint

        content_type: None | str | Unset
        if isinstance(self.content_type, Unset):
            content_type = UNSET
        else:
            content_type = self.content_type

        requested_server_name: None | str | Unset
        if isinstance(self.requested_server_name, Unset):
            requested_server_name = UNSET
        else:
            requested_server_name = self.requested_server_name

        server_fingerprint: None | str | Unset
        if isinstance(self.server_fingerprint, Unset):
            server_fingerprint = UNSET
        else:
            server_fingerprint = self.server_fingerprint

        user_agent: None | str | Unset
        if isinstance(self.user_agent, Unset):
            user_agent = UNSET
        else:
            user_agent = self.user_agent

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "application_category_name": application_category_name,
                "application_confidence": application_confidence,
                "application_is_guessed": application_is_guessed,
                "application_name": application_name,
                "bidirectional_bytes": bidirectional_bytes,
                "bidirectional_packets": bidirectional_packets,
                "dst2src_bytes": dst2src_bytes,
                "dst2src_packets": dst2src_packets,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "duration_ms": duration_ms,
                "expiration_reason": expiration_reason,
                "first_seen_ms": first_seen_ms,
                "flow_id": flow_id,
                "ip_version": ip_version,
                "last_seen_ms": last_seen_ms,
                "protocol": protocol,
                "protocol_name": protocol_name,
                "src2dst_bytes": src2dst_bytes,
                "src2dst_packets": src2dst_packets,
                "src_ip": src_ip,
                "src_port": src_port,
                "vlan_id": vlan_id,
            }
        )
        if client_fingerprint is not UNSET:
            field_dict["client_fingerprint"] = client_fingerprint
        if content_type is not UNSET:
            field_dict["content_type"] = content_type
        if requested_server_name is not UNSET:
            field_dict["requested_server_name"] = requested_server_name
        if server_fingerprint is not UNSET:
            field_dict["server_fingerprint"] = server_fingerprint
        if user_agent is not UNSET:
            field_dict["user_agent"] = user_agent

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        application_category_name = d.pop("application_category_name")

        application_confidence = d.pop("application_confidence")

        application_is_guessed = d.pop("application_is_guessed")

        application_name = d.pop("application_name")

        bidirectional_bytes = d.pop("bidirectional_bytes")

        bidirectional_packets = d.pop("bidirectional_packets")

        dst2src_bytes = d.pop("dst2src_bytes")

        dst2src_packets = d.pop("dst2src_packets")

        dst_ip = d.pop("dst_ip")

        dst_port = d.pop("dst_port")

        duration_ms = d.pop("duration_ms")

        expiration_reason = check_expiration_reason(d.pop("expiration_reason"))

        first_seen_ms = d.pop("first_seen_ms")

        flow_id = d.pop("flow_id")

        ip_version = d.pop("ip_version")

        last_seen_ms = d.pop("last_seen_ms")

        protocol = d.pop("protocol")

        protocol_name = d.pop("protocol_name")

        src2dst_bytes = d.pop("src2dst_bytes")

        src2dst_packets = d.pop("src2dst_packets")

        src_ip = d.pop("src_ip")

        src_port = d.pop("src_port")

        vlan_id = d.pop("vlan_id")

        def _parse_client_fingerprint(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        client_fingerprint = _parse_client_fingerprint(d.pop("client_fingerprint", UNSET))

        def _parse_content_type(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        content_type = _parse_content_type(d.pop("content_type", UNSET))

        def _parse_requested_server_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        requested_server_name = _parse_requested_server_name(d.pop("requested_server_name", UNSET))

        def _parse_server_fingerprint(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        server_fingerprint = _parse_server_fingerprint(d.pop("server_fingerprint", UNSET))

        def _parse_user_agent(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        user_agent = _parse_user_agent(d.pop("user_agent", UNSET))

        flow = cls(
            application_category_name=application_category_name,
            application_confidence=application_confidence,
            application_is_guessed=application_is_guessed,
            application_name=application_name,
            bidirectional_bytes=bidirectional_bytes,
            bidirectional_packets=bidirectional_packets,
            dst2src_bytes=dst2src_bytes,
            dst2src_packets=dst2src_packets,
            dst_ip=dst_ip,
            dst_port=dst_port,
            duration_ms=duration_ms,
            expiration_reason=expiration_reason,
            first_seen_ms=first_seen_ms,
            flow_id=flow_id,
            ip_version=ip_version,
            last_seen_ms=last_seen_ms,
            protocol=protocol,
            protocol_name=protocol_name,
            src2dst_bytes=src2dst_bytes,
            src2dst_packets=src2dst_packets,
            src_ip=src_ip,
            src_port=src_port,
            vlan_id=vlan_id,
            client_fingerprint=client_fingerprint,
            content_type=content_type,
            requested_server_name=requested_server_name,
            server_fingerprint=server_fingerprint,
            user_agent=user_agent,
        )

        flow.additional_properties = d
        return flow

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
