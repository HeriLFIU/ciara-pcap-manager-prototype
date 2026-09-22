from typing import Literal

JobStatus = Literal["failed", "pending", "running", "succeeded"]

JOB_STATUS_VALUES: set[JobStatus] = {
    "failed",
    "pending",
    "running",
    "succeeded",
}


def check_job_status(value: str) -> JobStatus:
    if value in JOB_STATUS_VALUES:
        return value
    raise TypeError(f"Unexpected value {value!r}. Expected one of {JOB_STATUS_VALUES!r}")
