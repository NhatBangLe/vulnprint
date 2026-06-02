from abc import ABC, abstractmethod
from typing import List, Optional, Tuple

try:
    from src.models import ExploitDetails, VulnerabilityRecord
except ImportError:
    from models import ExploitDetails, VulnerabilityRecord


class VulnerabilityRepository(ABC):
    """
    Abstract base class defining the interface for storing and retrieving
    vulnerability target profiles and query analytics.
    """

    @abstractmethod
    def initialize(self) -> None:
        """
        Ensures the repository storage/database schema is initialized.
        """
        pass

    @abstractmethod
    def store_vulnerability(
        self,
        msf_path: str,
        cves_list: List[str],
        data: ExploitDetails,
        raw_description: str,
    ) -> None:
        """
        Stores or updates a vulnerability target profile.
        """
        pass

    @abstractmethod
    def get_vulnerability(self, msf_path: str) -> Optional[VulnerabilityRecord]:
        """
        Retrieves a vulnerability target profile by its Metasploit path.
        """
        pass

    @abstractmethod
    def get_total_count(self) -> int:
        """
        Returns the total number of vulnerability target profiles stored.
        """
        pass

    @abstractmethod
    def get_top_technologies(self, limit: int = 10) -> List[Tuple[str, int]]:
        """
        Returns the top target technologies by vulnerability count.
        """
        pass
