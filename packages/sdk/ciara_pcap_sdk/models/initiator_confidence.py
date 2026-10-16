from typing import Literal

InitiatorConfidence = Literal["observed_first_packet", "tcp_syn_noack_observed", "unknown"]

INITIATOR_CONFIDENCE_VALUES: set[InitiatorConfidence] = {
    "observed_first_packet",
    "tcp_syn_noack_observed",
    "unknown",
}


def check_initiator_confidence(value: str) -> InitiatorConfidence:
    if value in INITIATOR_CONFIDENCE_VALUES:
        return value
    raise TypeError(f"Unexpected value {value!r}. Expected one of {INITIATOR_CONFIDENCE_VALUES!r}")
