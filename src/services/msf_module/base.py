from abc import ABC, abstractmethod
from typing import List, Tuple, Optional
from models import MetasploitModuleDetails


class MSFModuleService(ABC):
    """
    Interface for MSF module details service.
    Deals exclusively with the MetasploitModuleDetails domain model.
    """

    @abstractmethod
    def store_module_details(self, details: MetasploitModuleDetails) -> None:
        """
        Converts details to record DTO and stores it in the database layer.
        """
        pass

    @abstractmethod
    def get_module_details(self, path: str) -> Optional[MetasploitModuleDetails]:
        """
        Retrieves database DTOs and converts/returns a domain model.
        """
        pass

    @abstractmethod
    def get_all_paths(self) -> List[str]:
        """
        Retrieves all module paths.
        """
        pass

    @abstractmethod
    def get_total_count(self) -> int:
        """
        Retrieves the total count of modules.
        """
        pass

    @abstractmethod
    def get_rank_distribution(self) -> List[Tuple[str, int]]:
        """
        Retrieves exploit rank distribution statistics.
        """
        pass

    @abstractmethod
    def get_platform_distribution(self) -> List[Tuple[str, int]]:
        """
        Retrieves platform distribution statistics.
        """
        pass

    @abstractmethod
    def get_disclosure_timeline(self) -> List[Tuple[str, int]]:
        """
        Retrieves disclosure timeline statistics.
        """
        pass

    @abstractmethod
    def search_modules(
        self,
        software_pattern: Optional[str] = None,
        platform: Optional[str] = None,
        rank: Optional[str] = None,
    ) -> List[MetasploitModuleDetails]:
        """
        Searches modules and returns their details as domain models.
        """
        pass
