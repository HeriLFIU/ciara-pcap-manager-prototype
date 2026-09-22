"""
Shared core library for the CIARA PCAP analysis platform.

This package is deliberately free of any web-framework, HTTP-client or GUI
imports. It holds the domain models that define the API contract, the NFStream
extraction pipeline, and the job abstractions that the API, the CLI, the GUI
and any future worker process all build on.
"""

from ciara_pcap_manager_prototype.domain.flows import Flow, FlowPage, FlowSummary
from ciara_pcap_manager_prototype.domain.jobs import AnalysisJob, JobStatus

__all__ = [
    "AnalysisJob",
    "Flow",
    "FlowPage",
    "FlowSummary",
    "JobStatus",
]
