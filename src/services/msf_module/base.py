from abc import ABC, abstractmethod
from typing import List, Tuple, Optional
from models import (
    MetasploitModuleDetails,
    MSFModule,
    Software,
    SoftwareGuideline,
    OSGuideline,
)


class MSFModuleService(ABC):
    """
    Interface for MSF module details service.
    Deals exclusively with the MetasploitModuleDetails domain model.
    """

    @abstractmethod
    def store_module(self, data: MetasploitModuleDetails | MSFModule) -> Optional[int]:
        """
        Stores Metasploit module details.

        Args:
            data: Either a MetasploitModuleDetails domain object or an MSFModule.

        Returns:
            ID of the stored module.
        """
        pass

    @abstractmethod
    def get_module_by_id(self, module_id: int) -> Optional[MSFModule]:
        """
        Retrieves database DTO and converts/returns a domain model.
        """
        pass

    @abstractmethod
    def get_module_by_path(self, path: str) -> Optional[MSFModule]:
        """
        Retrieves database DTO and converts/returns a domain model.
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
    ) -> List[
        Tuple[
            MSFModule,
            Optional[Software],
            Optional[SoftwareGuideline],
            Optional[OSGuideline],
        ]
    ]:
        """
        Searches modules and returns their details as domain models.
        """
        pass
