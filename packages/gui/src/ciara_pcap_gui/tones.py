"""
Semantic tones: which colour family a categorical value is drawn in.

Tables, pills and breakdown bars all colour a protocol, a termination reason
or a job status the same way, so the mapping lives here once and the theme
turns each tone into a foreground and a background colour.
"""

from enum import StrEnum


class Tone(StrEnum):
    """A colour family of the theme."""

    ACCENT = "accent"
    SECONDARY = "secondary"
    SUCCESS = "success"
    WARNING = "warning"
    DANGER = "danger"
    NEUTRAL = "neutral"


_PROTOCOLS = {"TCP": Tone.ACCENT, "UDP": Tone.SECONDARY}

_TERMINATIONS = {
    "tcp_fin_both": Tone.SUCCESS,
    "tcp_rst": Tone.DANGER,
    "active_timeout": Tone.WARNING,
    "inactive_timeout": Tone.NEUTRAL,
    "end_of_input": Tone.NEUTRAL,
}

_JOB_STATUSES = {
    "succeeded": Tone.SUCCESS,
    "failed": Tone.DANGER,
    "running": Tone.WARNING,
    "pending": Tone.NEUTRAL,
}


def protocol_tone(label: str) -> Tone:
    """
    Colour a transport protocol.

    Args:
        label: ``TCP``, ``UDP`` or another protocol label.

    Returns:
        Accent for TCP, secondary for UDP, neutral otherwise.

    """
    return _PROTOCOLS.get(label, Tone.NEUTRAL)


def termination_tone(reason: str) -> Tone:
    """
    Colour the reason a flow segment ended.

    A clean TCP close reads as success, a reset as danger, and an active
    timeout (a long-lived flow cut short) as a warning.

    Args:
        reason: The ``termination_reason`` value.

    Returns:
        The tone.

    """
    return _TERMINATIONS.get(reason, Tone.NEUTRAL)


def job_tone(status: str) -> Tone:
    """
    Colour an analysis job's status.

    Args:
        status: The job status.

    Returns:
        The tone.

    """
    return _JOB_STATUSES.get(status, Tone.NEUTRAL)
