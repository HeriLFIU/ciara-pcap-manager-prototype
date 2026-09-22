from typing import Literal

ExpirationReason = Literal["active_timeout", "custom", "idle_timeout", "unknown"]

EXPIRATION_REASON_VALUES: set[ExpirationReason] = {
    "active_timeout",
    "custom",
    "idle_timeout",
    "unknown",
}


def check_expiration_reason(value: str) -> ExpirationReason:
    if value in EXPIRATION_REASON_VALUES:
        return value
    raise TypeError(f"Unexpected value {value!r}. Expected one of {EXPIRATION_REASON_VALUES!r}")
