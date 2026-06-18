from abc import ABC, abstractmethod
from typing import List, Optional, Tuple
from models import SoftwareMetadataRecord


class SoftwareMetadataRepository(ABC):
    """
    Interface for handling software metadata records.
    """

    @abstractmethod
    def store_software_metadata(self, record: SoftwareMetadataRecord) -> None:
        """
        Stores or updates software metadata in the database.
        """
        pass

    @abstractmethod
    def get_software_metadata(self, msf_path: str) -> Optional[SoftwareMetadataRecord]:
        """
        Retrieves software metadata for the given module path.
        """
        pass

    @abstractmethod
    def get_top_technologies(self, limit: int = 10) -> List[Tuple[str, int]]:
        """
        Queries top software/technologies by count.
        """
        pass

    @abstractmethod
    def get_all_software(self) -> List[str]:
        """
        Retrieves unique software names.
        """
        pass
