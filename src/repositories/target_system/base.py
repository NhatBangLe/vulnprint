from abc import ABC, abstractmethod
from typing import Optional
from models import TargetSystemRecord


class TargetSystemRepository(ABC):
    """
    Interface for handling target system hardware/OS platform metadata records.
    """

    @abstractmethod
    def save(self, record: TargetSystemRecord) -> Optional[int]:
        """
        Stores target system details and returns its unique ID.
        """
        pass

    @abstractmethod
    def get_by_id(self, target_system_id: int) -> Optional[TargetSystemRecord]:
        """
        Retrieves a target system record by ID.
        """
        pass

    @abstractmethod
    def exists(self, record: TargetSystemRecord) -> Optional[int]:
        """
        Checks if a target system with matching components already exists.
        Returns its ID if found, otherwise None.
        """
        pass
