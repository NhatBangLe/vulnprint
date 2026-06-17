from abc import ABC, abstractmethod
from typing import List, Optional
from models import VMGuideline


class VMGuidelineService(ABC):
    """
    Interface for VM guidelines service.
    Deals exclusively with the VMGuideline domain model.
    """

    @abstractmethod
    def store_vm_guideline(self, vm_guideline: VMGuideline) -> None:
        """
        Converts guideline to record DTO and stores it in the database layer.
        """
        pass

    @abstractmethod
    def get_vm_guideline(self, msf_path: str) -> Optional[VMGuideline]:
        """
        Retrieves database DTO record and converts/returns a domain model.
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
