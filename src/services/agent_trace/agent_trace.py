import logging
from typing import List, Optional, Dict, Any
from repositories import AgentTraceRepository
from models import AgentTraceRecord, AgentTrace, FailedModuleSummary
from utils.agent_tracer import AgentExecutionTrace
from .base import AgentTraceService


class DefaultAgentTraceService(AgentTraceService):
    """
    Default implementation of AgentTraceService.
    """

    def __init__(self, trace_repo: AgentTraceRepository):
        self.trace_repo = trace_repo
        self._logger = logging.getLogger(self.__class__.__name__)

    def record_trace(self, trace: AgentExecutionTrace, msf_path: str) -> Optional[int]:
        try:
            failed_step = trace.failed_step
            record = AgentTraceRecord(
                msf_path=msf_path,
                agent_name=trace.agent_name,
                status="SUCCESS" if trace.success else "FAILED",
                failed_step_name=failed_step.name if failed_step else None,
                failed_step_index=failed_step.index if failed_step else None,
                error_category=failed_step.error_category if failed_step else None,
                error_message=failed_step.error_message if failed_step else None,
                diagnostic_hint=failed_step.diagnostic_hint if failed_step else None,
                duration_seconds=trace.duration_seconds,
                trace_json=trace.to_json(),
            )
            trace_id = self.trace_repo.save(record)
            if trace_id:
                self._logger.debug(
                    f"Saved trace ID {trace_id} for '{msf_path}' ({trace.agent_name}: {record.status})"
                )
            return trace_id
        except Exception as e:
            self._logger.error(
                f"Error recording agent execution trace for '{msf_path}': {e}"
            )
            return None

    def get_traces_by_path(self, msf_path: str) -> List[AgentTrace]:
        records = self.trace_repo.get_by_path(msf_path)
        return [AgentTrace.from_record(r) for r in records]

    def get_latest_trace_for_module(
        self, msf_path: str, agent_name: Optional[str] = None
    ) -> Optional[AgentExecutionTrace]:
        record = self.trace_repo.get_latest_by_path(msf_path, agent_name)
        if not record or not record.trace_json:
            return None
        try:
            return AgentExecutionTrace.from_json(record.trace_json)
        except Exception as e:
            self._logger.error(
                f"Error deserializing stored trace JSON for '{msf_path}': {e}"
            )
            return None

    def get_failed_modules(
        self,
        pattern: Optional[str] = None,
        platform: Optional[str] = None,
        agent: Optional[str] = None,
        error_category: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[FailedModuleSummary]:
        raw_results = self.trace_repo.get_failed_traces(
            pattern=pattern,
            platform=platform,
            agent_name=agent,
            error_category=error_category,
            limit=limit,
        )
        summaries = []
        for trace_rec, module_rec in raw_results:
            summary = FailedModuleSummary(
                msf_path=trace_rec.msf_path,
                display_name=module_rec.display_name if module_rec else "",
                platforms=module_rec.platforms if module_rec else [],
                agent_name=trace_rec.agent_name,
                status=trace_rec.status,
                failed_step_name=trace_rec.failed_step_name or "Unknown",
                failed_step_index=trace_rec.failed_step_index or 0,
                error_category=trace_rec.error_category or "ExecutionError",
                error_message=trace_rec.error_message or "",
                diagnostic_hint=trace_rec.diagnostic_hint,
                duration_seconds=trace_rec.duration_seconds,
                created_at=trace_rec.created_at,
            )
            summaries.append(summary)
        return summaries

    def get_failure_stats(self) -> Dict[str, Any]:
        return self.trace_repo.get_failure_statistics()
