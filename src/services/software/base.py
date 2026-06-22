from abc import ABC, abstractmethod
from typing import List, Tuple, Optional
from models import Software


class SoftwareService(ABC):
    @abstractmethod
    def store_software(self, target: Software) -> None:
        """
        Converts domain model to records and stores them in the database layer.
        """
        pass

    @abstractmethod
    def get_software_by_id(self, software_id: int) -> Optional[Software]:
        """
        Retrieves database DTOs and converts/returns a domain model.
        """
        pass

    @abstractmethod
    def get_software_by_path(self, path: str) -> Optional[Software]:
        """
        Retrieves database DTOs and converts/returns a domain model.
        """
        pass

    @abstractmethod
    def get_top_software(self, limit: int = 10) -> List[Tuple[str, int]]:
        """
        Retrieves top technologies target sorted by exploit count.
        """
        pass

    @abstractmethod
    def get_all_software(self) -> List[str]:
        """
        Retrieves unique sorted software names.
        """
        pass

    @abstractmethod
    def get_required_configurations(self) -> List[str]:
        """
        Retrieves all configuration requirements.
        """
        pass
