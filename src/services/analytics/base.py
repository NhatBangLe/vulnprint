from abc import ABC, abstractmethod
from typing import Optional


class AnalyticsService(ABC):
    """
    Abstract base class defining the interface for displaying and querying
    vulnerability intelligence statistics and dashboards.
    """

    @abstractmethod
    def display_dashboard(self) -> None:
        """
        Displays the statistical analytics dashboard (e.g. CLI ASCII table).
        """
        pass

    @abstractmethod
    def display_analytics(self, export_path: Optional[str] = None) -> None:
        """
        Displays detailed statistical metrics dashboard panels.
        """
        pass

    @abstractmethod
    def display_software_list(self, export_path: Optional[str] = None) -> None:
        """
        Displays a list of all unique software targets.
        """
        pass

    @abstractmethod
    def display_search_results(
        self,
        software_pattern: Optional[str] = None,
        platform: Optional[str] = None,
        rank: Optional[str] = None,
        min_date: Optional[str] = None,
        max_date: Optional[str] = None,
        msf_path: Optional[str] = None,
        no_guideline: bool = False,
        export_path: Optional[str] = None,
    ) -> None:
        """
        Displays wildcard search results with optional platform, rank, date, msf_path, and no_guideline filters.
        """
        pass
