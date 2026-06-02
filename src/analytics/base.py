from abc import ABC, abstractmethod


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
