from abc import ABC, abstractmethod
from typing import List, Optional
from models import SoftwareGuidelineRecord, VMGuidelineMetadata


class SoftwareGuidelineRepository(ABC):
    """
    Interface for handling software installation guideline records.
    """

    @abstractmethod
    def store_software_guideline(self, record: SoftwareGuidelineRecord, path: str) -> int:
        """
        Stores a software installation guideline, links it to a module path, and returns its ID.
        """
        pass

    @abstractmethod
    def get_software_guideline(self, guideline_id: int) -> Optional[SoftwareGuidelineRecord]:
        """
        Retrieves a software guideline for the given ID.
        """
        pass

    @abstractmethod
    def get_software_guidelines_by_path(self, msf_path: str) -> List[SoftwareGuidelineRecord]:
        """
        Retrieves all software guidelines associated with the given module path.
        """
        pass

    @abstractmethod
    def get_unverified_guidelines(self) -> List[SoftwareGuidelineRecord]:
        """
        Retrieves all software guidelines marked as UNVERIFIED.
        """
        pass

    @abstractmethod
    def update_guideline_status(
        self, msf_path: str, status: str, guideline: Optional[str] = None
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
    def get_guidelines_with_software_metadata(self) -> List[VMGuidelineMetadata]:
        """
        Retrieves all software guidelines and their associated module/software/OS metadata mapping.
        """
        pass
