from abc import ABC, abstractmethod
from typing import List, Optional, Tuple
from models import (
    MSFModuleRecord,
    SoftwareRecord,
    VMGuidelineRecord,
)


class MSFModuleRepository(ABC):
    """
    Interface for handling MSF module metadata records.
    """

    @abstractmethod
    def store_module_metadata(self, record: MSFModuleRecord) -> None:
        """
        Stores or updates module metadata in the database.
        """
        pass

    @abstractmethod
    def get_module_metadata(self, msf_path: str) -> Optional[MSFModuleRecord]:
        """
        Retrieves module metadata for the given module path.
        """
        pass

    @abstractmethod
    def get_all_paths(self) -> List[str]:
        """
        Retrieves all registered Metasploit module paths.
        """
        pass

    @abstractmethod
    def get_total_count(self) -> int:
        """
        Returns the total count of modules.
        """
        pass

    @abstractmethod
    def get_rank_distribution(self) -> List[Tuple[str, int]]:
        """
        Returns the ranking distribution of Metasploit modules.
        """
        pass

    @abstractmethod
    def get_platform_distribution(self) -> List[Tuple[str, int]]:
        """
        Returns the platforms distribution of Metasploit modules.
        """
        pass

    @abstractmethod
    def get_disclosure_timeline(self) -> List[Tuple[str, int]]:
        """
        Returns module counts grouped by disclosure year.
        """
        pass

    @abstractmethod
    def search_modules(
        self,
        software_pattern: Optional[str] = None,
        platform: Optional[str] = None,
        rank: Optional[str] = None,
    ) -> List[
        Tuple[
            MSFModuleRecord,
            Optional[SoftwareRecord],
            Optional[VMGuidelineRecord],
        ]
    ]:
        """
        Searches modules joining software and guideline tables.
        Returns a list of tuples containing records.
        """
        pass
