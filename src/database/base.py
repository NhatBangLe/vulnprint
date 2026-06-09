from abc import ABC, abstractmethod
from typing import List, Optional, Tuple

try:
    from src.models import ExploitDetails, VulnerabilityRecord, MetasploitModuleDetails
except ImportError:
    from models import ExploitDetails, VulnerabilityRecord, MetasploitModuleDetails


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
        data: ExploitDetails,
        details: MetasploitModuleDetails,
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

    @abstractmethod
    def get_all_software(self) -> List[str]:
        """
        Retrieves a sorted list of all unique software names stored in the database.
        """
        pass

    @abstractmethod
    def search_vulnerabilities(
        self,
        software_pattern: Optional[str] = None,
        platform: Optional[str] = None,
        rank: Optional[str] = None,
    ) -> List[VulnerabilityRecord]:
        """
        Searches vulnerabilities by software name pattern (supporting wildcards) and filters.
        """
        pass

    @abstractmethod
    def get_rank_distribution(self) -> List[Tuple[str, int]]:
        """
        Retrieves exploit reliability ranks and their counts.
        """
        pass

    @abstractmethod
    def get_platform_distribution(self) -> List[Tuple[str, int]]:
        """
        Retrieves platforms and their counts.
        """
        pass

    @abstractmethod
    def get_disclosure_timeline(self) -> List[Tuple[str, int]]:
        """
        Retrieves vulnerability counts grouped by disclosure year.
        """
        pass

    @abstractmethod
    def get_required_configurations(self) -> List[str]:
        """
        Retrieves all JSON strings of required configuration flags.
        """
        pass
