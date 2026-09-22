"""
Job orchestration abstractions.

The protocols here are the seam between "analysis was requested" and "analysis
happened somewhere". Today the only implementation keeps state in memory; a
Redis- or database-backed implementation slots in behind the same interface
when the platform grows a worker fleet.
"""

from ciara_pcap_manager_prototype.jobs.memory import InMemoryJobStore
from ciara_pcap_manager_prototype.jobs.store import JobNotFoundError, JobStore

__all__ = ["InMemoryJobStore", "JobNotFoundError", "JobStore"]
