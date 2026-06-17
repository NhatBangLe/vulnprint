from abc import ABC, abstractmethod
from typing import List, Optional
from models import VMGuidelineRecord


class VMGuidelineRepository(ABC):
    """
    Interface for handling VM installation guideline records.
    """

    @abstractmethod
    def store_vm_guideline(self, record: VMGuidelineRecord) -> None:
        """
        Stores or updates a VM installation guideline.
        """
        pass

    @abstractmethod
    def get_vm_guideline(self, msf_path: str) -> Optional[VMGuidelineRecord]:
        """
        Retrieves a VM guideline for the given path.
        """
        pass

    @abstractmethod
    def get_unverified_guidelines(self) -> List[VMGuidelineRecord]:
        """
        Retrieves all guidelines marked as UNVERIFIED.
        """
        pass

    @abstractmethod
    def update_guideline_status(
        self, msf_path: str, status: str, guideline: Optional[str] = None
    ) -> None:
        """
        Updates the status (and optionally modifies text) of a VM guideline.
        """
        pass
