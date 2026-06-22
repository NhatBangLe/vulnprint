from abc import ABC, abstractmethod
from typing import List, Optional, Tuple
from models import SoftwareRecord


class SoftwareRepository(ABC):
    """
    Interface for handling software and vulnerability details records.
    """

    @abstractmethod
    def save(self, record: SoftwareRecord) -> int:
        """
        Stores or updates software vulnerability details in the database.
        """
        pass

    @abstractmethod
    def exists_by_id(self, software_id: int) -> bool:
        """
        Checks if software details exists for the given software id.
        """
        pass

    @abstractmethod
    def exists_by_path(self, msf_path: str) -> Optional[int]:
        """
        Checks if software details exists for the given module path.
        """
        pass

    @abstractmethod
    def get_by_id(self, software_id: int) -> Optional[SoftwareRecord]:
        """
        Retrieves software details for the given software id.
        """
        pass

    @abstractmethod
    def get_by_path(self, msf_path: str) -> Optional[SoftwareRecord]:
        """
        Retrieves software details for the given module path.
        """
        pass

    @abstractmethod
    def get_top_software(self, limit: int = 10) -> List[Tuple[str, int]]:
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

    @abstractmethod
    def get_required_configurations(self) -> List[str]:
        """
        Retrieves all configuration flags in the software table.
        """
        pass
