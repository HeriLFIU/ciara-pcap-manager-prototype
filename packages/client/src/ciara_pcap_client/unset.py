"""
Narrowing helpers for the generated SDK's ``UNSET`` sentinel.

``openapi-python-client`` types every optional property as ``T | Unset`` and
uses the ``UNSET`` singleton for "the server did not send this". That is a
faithful encoding of the wire format, but it means presentation code has to
narrow before it can format anything. These helpers do that in one place
instead of scattering ``isinstance`` checks through the CLI and the GUI.
"""

from ciara_pcap_sdk.types import Unset

__all__ = ["is_set", "value_or"]


def is_set(value: object) -> bool:
    """
    Report whether the backend actually sent a value.

    Args:
        value: A field read from a generated model.

    Returns:
        True when the field carries a real value.

    """
    return not isinstance(value, Unset) and value is not None


def value_or[T](value: T | Unset | None, default: T) -> T:
    """
    Narrow an optional SDK field to a concrete value.

    Args:
        value: A field read from a generated model.
        default: What to use when the field was absent or null.

    Returns:
        The field's value, or the default.

    """
    if isinstance(value, Unset) or value is None:
        return default
    return value
