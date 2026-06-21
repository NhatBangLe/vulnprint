from abc import ABC, abstractmethod
from typing import List, Optional
from models import VMGuideline, VMGuidelineCoverageStats


class VMGuidelineService(ABC):
    """
    Interface for VM guidelines service.
    """

    @abstractmethod
    def store_vm_guideline(self, vm_guideline: VMGuideline) -> None:
        """
        Converts guideline to record DTO and stores it in the database layer.
        """
        pass

    @abstractmethod
    def get_vm_guideline(self, guideline_id: int) -> Optional[VMGuideline]:
        """
        Retrieves database DTO record and converts/returns a domain model.
        """
        pass

    @abstractmethod
    def get_vm_guideline_by_path(self, msf_path: str) -> List[VMGuideline]:
        """
        Retrieves database DTO records by path and converts/returns domain models.
        """
        pass

    @abstractmethod
    def get_unverified_guidelines(self) -> List[VMGuideline]:
        """
        Retrieves all unverified guidelines as domain models.
        """
        pass

    @abstractmethod
    def update_guideline_status(
        self, msf_path: str, status: str, guideline_text: Optional[str] = None
    ) -> None:
        """
        Updates guideline status.
        """
        pass

    @abstractmethod
    def link_guideline_to_module(self, msf_path: str, guideline_id: int) -> None:
        """
        Links an existing guideline to an MSF module path.
        """
        pass

    @abstractmethod
    def find_suitable_guideline(
        self, platform: List[str], software_name: str, vulnerable_versions: List[str]
    ) -> Optional[VMGuideline]:
        """
        Finds a suitable existing VM guideline in the database based on scoring compatibility.
        """
        pass

    @abstractmethod
    def get_guideline_coverage_stats(self) -> VMGuidelineCoverageStats:
        """
        Compiles guideline coverage metrics and returns them in a Pydantic container.
        """
        pass
