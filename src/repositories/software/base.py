from abc import ABC, abstractmethod
from typing import List, Optional, Tuple
from models import SoftwareRecord


class SoftwareRepository(ABC):
    """
    Interface for handling software and vulnerability details records.
    """

    @abstractmethod
    def store_software_details(self, record: SoftwareRecord) -> None:
        """
        Stores or updates software vulnerability details in the database.
        """
        pass

    @abstractmethod
    def get_software_details(self, msf_path: str) -> Optional[SoftwareRecord]:
        """
        Retrieves software details for the given module path.
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

    @abstractmethod
    def get_required_configurations(self) -> List[str]:
        """
        Retrieves all configuration flags in the software table.
        """
        pass
