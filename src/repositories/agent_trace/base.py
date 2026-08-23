from abc import ABC, abstractmethod
from typing import List, Optional, Tuple, Dict, Any
from models import AgentTraceRecord, MSFModuleRecord


class AgentTraceRepository(ABC):
    """
    Interface for persisting and querying agent execution traces.
    """

    @abstractmethod
    def save(self, record: AgentTraceRecord) -> Optional[int]:
        """
        Saves an agent execution trace record to the database.
        """
        pass

    @abstractmethod
    def get_by_path(self, msf_path: str) -> List[AgentTraceRecord]:
        """
        Retrieves all trace records associated with an MSF module path.
        """
        pass

    @abstractmethod
    def get_latest_by_path(
        self, msf_path: str, agent_name: Optional[str] = None
    ) -> Optional[AgentTraceRecord]:
        """
        Retrieves the most recent trace record for an MSF module path.
        """
        pass

    @abstractmethod
    def get_failed_traces(
        self,
        pattern: Optional[str] = None,
        platform: Optional[str] = None,
        agent_name: Optional[str] = None,
        error_category: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[Tuple[AgentTraceRecord, Optional[MSFModuleRecord]]]:
        """
        Retrieves failed trace records matching the given criteria,
        joined with MSF module metadata.
        """
        pass

    @abstractmethod
    def get_failure_statistics(self) -> Dict[str, Any]:
        """
        Aggregates failure metrics across all agent runs (e.g. counts by agent, error categories).
        """
        pass
