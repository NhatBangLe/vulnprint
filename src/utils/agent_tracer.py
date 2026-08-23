import time
from enum import Enum
from typing import Dict, Any, List, Optional, TypeVar, Generic, Union
from dataclasses import dataclass, field
from contextlib import contextmanager


class StepStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


@dataclass
class StepExecution:
    name: str
    index: int
    status: StepStatus = StepStatus.PENDING
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    duration_seconds: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    error_category: Optional[str] = None
    error_message: Optional[str] = None
    diagnostic_hint: Optional[str] = None
    raw_output_snippet: Optional[str] = None

    def start(self, metadata: Optional[Dict[str, Any]] = None) -> None:
        self.start_time = time.time()
        self.status = StepStatus.RUNNING
        if metadata:
            self.metadata.update(metadata)

    def complete(self, metadata: Optional[Dict[str, Any]] = None) -> None:
        self.end_time = time.time()
        if self.start_time is not None:
            self.duration_seconds = round(self.end_time - self.start_time, 3)
        self.status = StepStatus.COMPLETED
        if metadata:
            self.metadata.update(metadata)

    def fail(
        self,
        error_message: str,
        error_category: Optional[str] = None,
        diagnostic_hint: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        raw_output_snippet: Optional[str] = None,
    ) -> None:
        self.end_time = time.time()
        if self.start_time is not None:
            self.duration_seconds = round(self.end_time - self.start_time, 3)
        self.status = StepStatus.FAILED
        self.error_message = error_message
        self.error_category = error_category
        self.diagnostic_hint = diagnostic_hint
        self.raw_output_snippet = raw_output_snippet
        if metadata:
            self.metadata.update(metadata)

    def skip(self, reason: Optional[str] = None) -> None:
        self.status = StepStatus.SKIPPED
        if reason:
            self.metadata["skip_reason"] = reason


@dataclass
class AgentExecutionTrace:
    agent_name: str
    target_identifier: str
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    duration_seconds: Optional[float] = None
    success: bool = False
    steps: List[StepExecution] = field(default_factory=list)
    failed_step: Optional[StepExecution] = None
    error_summary: Optional[str] = None

    def finish(self, success: bool = True, error_summary: Optional[str] = None) -> None:
        self.end_time = time.time()
        self.duration_seconds = round(self.end_time - self.start_time, 3)
        self.success = success
        self.error_summary = error_summary

        # Mark any remaining PENDING or RUNNING steps as SKIPPED or FAILED
        for step in self.steps:
            if step.status == StepStatus.PENDING:
                step.status = StepStatus.SKIPPED
            elif step.status == StepStatus.RUNNING:
                if not success:
                    step.status = StepStatus.FAILED
                else:
                    step.complete()

        # Identify failed step
        for step in self.steps:
            if step.status == StepStatus.FAILED:
                self.failed_step = step
                break

    def format_visual_box(self, use_color: bool = True) -> str:
        """
        Formats the execution trace into an easy-to-read ASCII/ANSI table box.
        """
        reset = "\033[0m" if use_color else ""
        green = "\033[32m" if use_color else ""
        red = "\033[31m" if use_color else ""
        yellow = "\033[33m" if use_color else ""
        cyan = "\033[36m" if use_color else ""
        dim = "\033[2m" if use_color else ""
        bold = "\033[1m" if use_color else ""

        total_dur = (
            f"{self.duration_seconds:.2f}s"
            if self.duration_seconds is not None
            else "N/A"
        )
        header_status = (
            f"{green}SUCCESS{reset}" if self.success else f"{red}FAILED{reset}"
        )

        lines = [
            f"┌── Trace: {bold}{self.agent_name}{reset} [{header_status}] Target: '{self.target_identifier}' ({total_dur}) ──",
        ]

        for step in self.steps:
            dur_str = (
                f" ({step.duration_seconds:.2f}s)"
                if step.duration_seconds is not None
                else ""
            )
            if step.status == StepStatus.COMPLETED:
                icon = f"{green}[✔]{reset}"
                status_text = f"Step {step.index}: {step.name}{dur_str}"
                lines.append(f"│ {icon} {status_text}")
                for k, v in step.metadata.items():
                    if k != "skip_reason":
                        lines.append(f"│     {dim}• {k}: {v}{reset}")
            elif step.status == StepStatus.FAILED:
                icon = f"{red}[✖]{reset}"
                status_text = f"Step {step.index}: {step.name}{dur_str} - {bold}{red}FAILED{reset}"
                lines.append(f"│ {icon} {status_text}")
                if step.error_category:
                    lines.append(
                        f"│     {red}• Error Category: {step.error_category}{reset}"
                    )
                if step.error_message:
                    lines.append(
                        f"│     {red}• Root Cause: {step.error_message}{reset}"
                    )
                if step.diagnostic_hint:
                    lines.append(
                        f"│     {yellow}• Diagnostic Hint: {step.diagnostic_hint}{reset}"
                    )
                if step.raw_output_snippet:
                    preview = (
                        step.raw_output_snippet[:200] + "..."
                        if len(step.raw_output_snippet) > 200
                        else step.raw_output_snippet
                    )
                    lines.append(f"│     {cyan}• Raw Output Preview: {preview}{reset}")
                for k, v in step.metadata.items():
                    lines.append(f"│     {dim}• {k}: {v}{reset}")
            elif step.status == StepStatus.SKIPPED:
                icon = f"{dim}[-]{reset}"
                reason = (
                    f" ({step.metadata.get('skip_reason')})"
                    if "skip_reason" in step.metadata
                    else ""
                )
                lines.append(
                    f"│ {icon} {dim}Step {step.index}: {step.name} (SKIPPED{reason}){reset}"
                )
            else:
                icon = f"{yellow}[?]{reset}"
                lines.append(
                    f"│ {icon} Step {step.index}: {step.name} ({step.status.value})"
                )

        lines.append("└" + "─" * 70)
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_name": self.agent_name,
            "target_identifier": self.target_identifier,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": self.duration_seconds,
            "success": self.success,
            "error_summary": self.error_summary,
            "failed_step": (
                {
                    "name": self.failed_step.name,
                    "index": self.failed_step.index,
                    "error_category": self.failed_step.error_category,
                    "error_message": self.failed_step.error_message,
                    "diagnostic_hint": self.failed_step.diagnostic_hint,
                }
                if self.failed_step
                else None
            ),
            "steps": [
                {
                    "name": s.name,
                    "index": s.index,
                    "status": s.status.value,
                    "duration_seconds": s.duration_seconds,
                    "metadata": s.metadata,
                    "error_category": s.error_category,
                    "error_message": s.error_message,
                    "diagnostic_hint": s.diagnostic_hint,
                    "raw_output_snippet": s.raw_output_snippet,
                }
                for s in self.steps
            ],
        }

    def to_json(self) -> str:
        import json

        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentExecutionTrace":
        trace = cls(
            agent_name=data.get("agent_name", "UnknownAgent"),
            target_identifier=data.get("target_identifier", "unknown_target"),
            start_time=data.get("start_time", 0.0),
            end_time=data.get("end_time"),
            duration_seconds=data.get("duration_seconds"),
            success=data.get("success", False),
            error_summary=data.get("error_summary"),
        )
        steps = []
        for s_data in data.get("steps", []):
            try:
                status = StepStatus(s_data.get("status", "PENDING"))
            except Exception:
                status = StepStatus.PENDING
            step = StepExecution(
                name=s_data.get("name", "UnknownStep"),
                index=s_data.get("index", len(steps) + 1),
                status=status,
                duration_seconds=s_data.get("duration_seconds"),
                metadata=s_data.get("metadata", {}),
                error_category=s_data.get("error_category"),
                error_message=s_data.get("error_message"),
                diagnostic_hint=s_data.get("diagnostic_hint"),
                raw_output_snippet=s_data.get("raw_output_snippet"),
            )
            steps.append(step)
            if step.status == StepStatus.FAILED and trace.failed_step is None:
                trace.failed_step = step

        trace.steps = steps
        return trace

    @classmethod
    def from_json(cls, json_str: str) -> "AgentExecutionTrace":
        import json

        data = json.loads(json_str)
        return cls.from_dict(data)


class AgentStepTracker:
    """
    Context helper to track step execution lifecycle within an agent run.
    """

    def __init__(
        self,
        agent_name: str,
        target_identifier: str,
        expected_steps: Optional[List[str]] = None,
    ):
        self.trace = AgentExecutionTrace(
            agent_name=agent_name,
            target_identifier=target_identifier,
        )
        self._steps_by_name: Dict[str, StepExecution] = {}
        if expected_steps:
            for idx, name in enumerate(expected_steps, 1):
                step = StepExecution(name=name, index=idx)
                self.trace.steps.append(step)
                self._steps_by_name[name] = step

    def _get_or_create_step(self, name: str) -> StepExecution:
        if name in self._steps_by_name:
            return self._steps_by_name[name]
        step = StepExecution(name=name, index=len(self.trace.steps) + 1)
        self.trace.steps.append(step)
        self._steps_by_name[name] = step
        return step

    def start_step(
        self, name: str, metadata: Optional[Dict[str, Any]] = None
    ) -> StepExecution:
        step = self._get_or_create_step(name)
        step.start(metadata)
        return step

    def complete_step(
        self, name: str, metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        step = self._get_or_create_step(name)
        step.complete(metadata)

    def fail_step(
        self,
        name: str,
        error: Union[Exception, str],
        error_category: Optional[str] = None,
        diagnostic_hint: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        raw_output_snippet: Optional[str] = None,
    ) -> None:
        step = self._get_or_create_step(name)
        error_msg = str(error)
        category = error_category or (
            type(error).__name__ if isinstance(error, Exception) else "ExecutionError"
        )
        step.fail(
            error_message=error_msg,
            error_category=category,
            diagnostic_hint=diagnostic_hint,
            metadata=metadata,
            raw_output_snippet=raw_output_snippet,
        )
        self.trace.failed_step = step
        self.trace.finish(
            success=False, error_summary=f"Step '{name}' failed: {error_msg}"
        )

    def skip_step(self, name: str, reason: Optional[str] = None) -> None:
        step = self._get_or_create_step(name)
        step.skip(reason)

    def finish(self, success: bool = True) -> AgentExecutionTrace:
        self.trace.finish(success=success)
        return self.trace

    def __enter__(self) -> "AgentStepTracker":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            if not self.trace.failed_step:
                self.trace.finish(success=False, error_summary=str(exc_val))
        elif self.trace.end_time is None:
            self.trace.finish(success=(self.trace.failed_step is None))

    @contextmanager
    def step(self, name: str, metadata: Optional[Dict[str, Any]] = None):
        """
        Convenience context manager for executing and tracking a step.
        """
        step = self.start_step(name, metadata)
        try:
            yield step
            if step.status == StepStatus.RUNNING:
                self.complete_step(name)
        except Exception as e:
            if step.status == StepStatus.RUNNING:
                self.fail_step(name, e)
            raise


T = TypeVar("T")


@dataclass
class AgentResult(Generic[T]):
    data: Optional[T]
    trace: AgentExecutionTrace
    error: Optional[Exception] = None

    @property
    def success(self) -> bool:
        return self.trace.success and self.data is not None
