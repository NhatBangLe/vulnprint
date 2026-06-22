from abc import ABC, abstractmethod
from typing import Optional
from models import OSGuidelineRecord


class OSGuidelineRepository(ABC):
    """
    Interface for handling OS installation guideline records.
    """

    @abstractmethod
    def exists_by_id(self, guideline_id: int) -> bool:
        """
        Checks if an OS guideline already exists for the given ID.
        """
        pass

    @abstractmethod
    def exists_by_name(self, os_name: str) -> Optional[int]:
        """
        Checks if an OS guideline already exists for the given OS name.
        """
        pass

    @abstractmethod
    def save(self, record: OSGuidelineRecord) -> Optional[int]:
        """
        Stores or updates an OS installation guideline and returns its ID.
        """
        pass

    @abstractmethod
    def get_by_id(self, guideline_id: int) -> Optional[OSGuidelineRecord]:
        """
        Retrieves an OS guideline for the given ID.
        """
        pass

    @abstractmethod
    def get_by_name(self, os_name: str) -> Optional[OSGuidelineRecord]:
        """
        Retrieves an OS guideline by its unique name.
        """
        pass
