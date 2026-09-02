from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from utils.agent_tracer import AgentExecutionTrace
from models import AgentTrace, FailedModuleSummary


class AgentTraceService(ABC):
    """
    Interface for recording, retrieving, and analyzing agent execution traces.
    """

    @abstractmethod
    def record_trace(self, trace: AgentExecutionTrace, msf_path: str) -> Optional[int]:
        """
        Persists an agent execution trace to the database.
        """
        pass

    @abstractmethod
    def get_traces_by_path(self, msf_path: str) -> List[AgentTrace]:
        """
        Retrieves all trace records for a specific Metasploit module path.
        """
        pass

    @abstractmethod
    def get_latest_trace_for_module(
        self, msf_path: str, agent_name: Optional[str] = None
    ) -> Optional[AgentExecutionTrace]:
        """
        Reconstructs the latest AgentExecutionTrace object for a module path from stored JSON.
        """
        pass

    @abstractmethod
    def get_failed_modules(
        self,
        pattern: Optional[str] = None,
        platform: Optional[str] = None,
        agent: Optional[str] = None,
        error_category: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[FailedModuleSummary]:
        """
        Retrieves failed module summaries matching the filtering criteria.
        """
        pass

    @abstractmethod
    def get_failure_stats(self) -> Dict[str, Any]:
        """
        Aggregates agent execution health and failure statistics.
        """
        pass

    @abstractmethod
    def get_all_traces(
        self,
        pattern: Optional[str] = None,
        agent_name: Optional[str] = None,
        status: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[AgentTrace]:
        """
        Retrieves all execution traces from the database matching optional filtering criteria.
        """
        pass

    @abstractmethod
    def export_all_traces(
        self,
        pattern: Optional[str] = None,
        agent_name: Optional[str] = None,
        status: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Exports all execution traces as a list of structured dictionaries.
        """
        pass
