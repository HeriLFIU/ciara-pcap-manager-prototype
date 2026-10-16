from typing import Literal

TerminationReason = Literal["active_timeout", "end_of_input", "inactive_timeout", "tcp_fin_both", "tcp_rst"]

TERMINATION_REASON_VALUES: set[TerminationReason] = {
    "active_timeout",
    "end_of_input",
    "inactive_timeout",
    "tcp_fin_both",
    "tcp_rst",
}


def check_termination_reason(value: str) -> TerminationReason:
    if value in TERMINATION_REASON_VALUES:
        return value
    raise TypeError(f"Unexpected value {value!r}. Expected one of {TERMINATION_REASON_VALUES!r}")
