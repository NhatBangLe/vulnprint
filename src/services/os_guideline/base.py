from abc import ABC, abstractmethod
from typing import List, Optional, Tuple
from models import OSGuideline


class OSGuidelineService(ABC):
    """
    Interface for OS guidelines service.
    """

    @abstractmethod
    def store_os_guideline(self, os_guideline: OSGuideline) -> int:
        """
        Stores OS guideline in the database layer and returns its ID.
        """
        pass

    @abstractmethod
    def get_os_guideline_by_id(self, guideline_id: int) -> Optional[OSGuideline]:
        """
        Retrieves OS guideline by ID and converts/returns a domain model.
        """
        pass

    @abstractmethod
    def find_all_potential_guidelines(
        self, target_system_id: Optional[int], platforms: List[str] = None
    ) -> List[Tuple[int, OSGuideline]]:
        """
        Finds all potential OS guidelines in the database matching the criteria.
        """
        pass
