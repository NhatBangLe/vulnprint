from abc import ABC, abstractmethod
from typing import List, Optional, Tuple
from models import (
    MSFModuleRecord,
    SoftwareRecord,
    OSGuidelineRecord,
    SoftwareGuidelineRecord,
)


class MSFModuleRepository(ABC):
    """
    Interface for handling MSF module metadata records.
    """

    @abstractmethod
    def save(self, record: MSFModuleRecord) -> Optional[int]:
        """
        Stores or updates module metadata in the database.
        """
        pass

    @abstractmethod
    def exists_by_id(self, module_id: int) -> bool:
        """
        Checks if a module with the given id exists.
        """
        pass

    @abstractmethod
    def exists_by_path(self, msf_path: str) -> Optional[int]:
        """
        Checks if a module with the given path exists.
        """
        pass

    @abstractmethod
    def get_by_id(self, module_id: int) -> Optional[MSFModuleRecord]:
        """
        Retrieves module metadata for the given module id.
        """
        pass

    @abstractmethod
    def get_by_path(self, msf_path: str) -> Optional[MSFModuleRecord]:
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
            Optional[SoftwareGuidelineRecord],
            Optional[OSGuidelineRecord],
        ]
    ]:
        """
        Searches modules joining software and guideline tables.
        Returns a list of tuples containing records.
        """
        pass
