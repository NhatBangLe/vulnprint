import logging

try:
    from src.analytics.base import AnalyticsService
    from src.database import VulnerabilityRepository
except ImportError:
    from .base import AnalyticsService
    from database import VulnerabilityRepository


class CLIAnalyticsService(AnalyticsService):
    """
    Concrete implementation of AnalyticsService displaying an ASCII dashboard in the terminal.
    """

    def __init__(self, repository: VulnerabilityRepository):
        self.repository = repository
        self._logger = logging.getLogger(self.__class__.__name__)

    def display_dashboard(self) -> None:
        """
        Queries technology density metrics from the VulnerabilityRepository
        and outputs a beautiful CLI ASCII dashboard of the Top 10 target landscapes.
        """
        try:
            total_count = self.repository.get_total_count()

            print("\n" + "=" * 70)
            print(f"{'VULNPRINT TECHNOLOGY DENSITY METRICS':^70}")
            print("=" * 70)
            print(f" Total Vulnerability Profiles Indexed: {total_count}")
            print("-" * 70)

            if total_count == 0:
                print(" No records found in the database. Run a search first.")
                print("=" * 70 + "\n")
                return

            # Query Top 10 technologies
            top_techs = self.repository.get_top_technologies(limit=10)

            # Header for the table
            print(f"{'Rank':<6}{'Software Target':<36}{'Count':<10}{'Percentage':<10}")
            print("-" * 70)

            for idx, (software_name, count) in enumerate(top_techs, 1):
                percentage = (count / total_count) * 100
                percentage_str = f"{percentage:.1f}%"
                # Truncate software target name if it is too long to prevent wrapping
                display_name = (
                    software_name[:34] + ".."
                    if len(software_name) > 34
                    else software_name
                )
                print(f"{idx:<6}{display_name:<36}{count:<10}{percentage_str:<10}")

            print("=" * 70 + "\n")

        except Exception as e:
            self._logger.error(f"Error displaying analytics: {e}")
