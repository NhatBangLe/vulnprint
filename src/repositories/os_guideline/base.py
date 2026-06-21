from abc import ABC, abstractmethod
from typing import Optional
from models import OSGuidelineRecord


class OSGuidelineRepository(ABC):
    """
    Interface for handling OS installation guideline records.
    """

    @abstractmethod
    def store_os_guideline(self, record: OSGuidelineRecord) -> int:
        """
        Stores or updates an OS installation guideline and returns its ID.
        """
        pass

    @abstractmethod
    def get_os_guideline(self, guideline_id: int) -> Optional[OSGuidelineRecord]:
        """
        Retrieves an OS guideline for the given ID.
        """
        pass

    @abstractmethod
    def get_os_guideline_by_name(self, os_name: str) -> Optional[OSGuidelineRecord]:
        """
        Retrieves an OS guideline by its unique name.
        """
        pass
