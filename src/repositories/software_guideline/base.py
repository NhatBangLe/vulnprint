from abc import ABC, abstractmethod
from typing import List, Optional
from models import SoftwareGuidelineRecord, SoftwareGuidelineMetadata


class SoftwareGuidelineRepository(ABC):
    """
    Interface for handling software installation guideline records.
    """

    @abstractmethod
    def save(self, record: SoftwareGuidelineRecord) -> Optional[int]:
        """
        Stores a software installation guideline, links it to a module path, and returns its ID.
        """
        pass

    @abstractmethod
    def exists_by_id(self, guideline_id: int) -> bool:
        """
        Checks if a software guideline with the given ID exists.
        """
        pass

    @abstractmethod
    def exists_by_path(self, msf_path: str) -> Optional[int]:
        """
        Checks if a software guideline with the given path exists and returns its ID.
        """
        pass

    @abstractmethod
    def get_by_id(self, guideline_id: int) -> Optional[SoftwareGuidelineRecord]:
        """
        Retrieves a software guideline for the given ID.
        """
        pass

    @abstractmethod
    def get_by_path(self, msf_path: str) -> List[SoftwareGuidelineRecord]:
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
    def link_guideline_to_module(self, msf_path: str, guideline_id: int) -> None:
        """
        Links an existing software guideline to an MSF module path.
        """
        pass

    @abstractmethod
    def get_by_os_guideline_id(
        self, os_guideline_id: int
    ) -> List[SoftwareGuidelineRecord]:
        """
        Retrieves all software guidelines associated with the given OS guideline ID.
        """
        pass

    @abstractmethod
    def get_guidelines_with_software_metadata(self) -> List[SoftwareGuidelineMetadata]:
        """
        Retrieves all software guidelines and their associated module/software/OS metadata mapping.
        """
        pass
