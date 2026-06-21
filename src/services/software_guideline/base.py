from abc import ABC, abstractmethod
from typing import List, Optional, Tuple
from models import SoftwareGuideline, VMGuidelineCoverageStats


class SoftwareGuidelineService(ABC):
    """
    Interface for software guidelines service.
    """

    @abstractmethod
    def store_software_guideline(self, software_guideline: SoftwareGuideline, path: str) -> int:
        """
        Stores software guideline and links it to a module path, returning its ID.
        """
        pass

    @abstractmethod
    def get_software_guideline(self, guideline_id: int) -> Optional[SoftwareGuideline]:
        """
        Retrieves software guideline by ID.
        """
        pass

    @abstractmethod
    def get_software_guidelines_by_path(self, msf_path: str) -> List[SoftwareGuideline]:
        """
        Retrieves software guidelines associated with the given module path.
        """
        pass

    @abstractmethod
    def get_unverified_guidelines(self) -> List[SoftwareGuideline]:
        """
        Retrieves all unverified software guidelines.
        """
        pass

    @abstractmethod
    def update_guideline_status(
        self, msf_path: str, status: str, guideline_text: Optional[str] = None
    ) -> None:
        """
        Updates the status (and optionally modifies text) of the latest software guideline linked to msf_path.
        """
        pass

    @abstractmethod
    def link_guideline_to_module(self, msf_path: str, guideline_id: int) -> None:
        """
        Links an existing software guideline to an MSF module path.
        """
        pass

    @abstractmethod
    def find_all_potential_guidelines(
        self, platform: List[str], software_name: str, vulnerable_versions: List[str]
    ) -> List[Tuple[int, SoftwareGuideline]]:
        """
        Finds all potential software guidelines in the database matching the criteria.
        """
        pass

    @abstractmethod
    def get_guideline_coverage_stats(self) -> VMGuidelineCoverageStats:
        """
        Compiles guideline coverage metrics.
        """
        pass
