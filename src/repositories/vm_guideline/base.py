from abc import ABC, abstractmethod
from typing import List, Optional
from models import VMGuidelineRecord, VMGuidelineMetadata


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
    def get_vm_guideline(self, guideline_id: int) -> Optional[VMGuidelineRecord]:
        """
        Retrieves a VM guideline for the given ID.
        """
        pass

    @abstractmethod
    def get_vm_guideline_by_path(self, msf_path: str) -> List[VMGuidelineRecord]:
        """
        Retrieves all VM guidelines for the given path.
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

    @abstractmethod
    def link_guideline_to_module(self, msf_path: str, guideline_id: int) -> None:
        """
        Links an existing guideline to an MSF module path.
        """
        pass

    @abstractmethod
    def get_guidelines_with_software_metadata(self) -> List[VMGuidelineMetadata]:
        """
        Retrieves all guidelines and their associated module/software metadata mapping.
        """
        pass
