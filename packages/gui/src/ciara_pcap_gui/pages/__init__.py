"""
The pages of the main window, in sidebar order.

Append a `Page` subclass to `PAGES` to add a page; see
:mod:`ciara_pcap_gui.pages.base` for the contract.
"""

from ciara_pcap_gui.pages.base import Page
from ciara_pcap_gui.pages.flows import FlowsPage
from ciara_pcap_gui.pages.history import HistoryPage
from ciara_pcap_gui.pages.overview import OverviewPage

PAGES: tuple[type[Page], ...] = (OverviewPage, FlowsPage, HistoryPage)

__all__ = ["PAGES", "FlowsPage", "HistoryPage", "OverviewPage", "Page"]
