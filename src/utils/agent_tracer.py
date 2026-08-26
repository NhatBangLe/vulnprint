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
class TokenUsage:
    """
    Tracks token usages (prompt, completion, and total tokens).
    """

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0

    def __post_init__(self) -> None:
        if self.total_tokens == 0 and (
            self.prompt_tokens > 0 or self.completion_tokens > 0
        ):
            self.total_tokens = self.prompt_tokens + self.completion_tokens

    @property
    def input_tokens(self) -> int:
        return self.prompt_tokens

    @property
    def output_tokens(self) -> int:
        return self.completion_tokens

    def add(
        self,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        total_tokens: Optional[int] = None,
    ) -> "TokenUsage":
        self.prompt_tokens += prompt_tokens
        self.completion_tokens += completion_tokens
        self.total_tokens += (
            total_tokens
            if total_tokens is not None
            else (prompt_tokens + completion_tokens)
        )
        return self

    def combine(self, other: Optional["TokenUsage"]) -> "TokenUsage":
        if other:
            self.add(
                prompt_tokens=other.prompt_tokens,
                completion_tokens=other.completion_tokens,
                total_tokens=other.total_tokens,
            )
        return self

    def to_dict(self) -> Dict[str, int]:
        return {
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
        }

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "TokenUsage":
        if not data:
            return cls()
        p = int(data.get("prompt_tokens") or data.get("input_tokens") or 0)
        c = int(data.get("completion_tokens") or data.get("output_tokens") or 0)
        t = int(data.get("total_tokens") or (p + c))
        return cls(prompt_tokens=p, completion_tokens=c, total_tokens=t)

    @property
    def is_empty(self) -> bool:
        return self.total_tokens == 0

    def __add__(self, other: "TokenUsage") -> "TokenUsage":
        if not isinstance(other, TokenUsage):
            return NotImplemented
        p = self.prompt_tokens + other.prompt_tokens
        c = self.completion_tokens + other.completion_tokens
        t = self.total_tokens + other.total_tokens
        return TokenUsage(
            prompt_tokens=p,
            completion_tokens=c,
            total_tokens=t if t > 0 else (p + c),
        )


def extract_token_usage_from_result(result: Any) -> TokenUsage:
    """
    Extracts and aggregates token usage (prompt, completion, total tokens)
    from an agent/LLM invocation result, messages list, or dictionary.
    """
    usage = TokenUsage()
    if result is None:
        return usage

    messages = []
    if isinstance(result, dict):
        messages = result.get("messages") or []
        if "usage_metadata" in result and isinstance(result["usage_metadata"], dict):
            um = result["usage_metadata"]
            usage.add(
                prompt_tokens=int(
                    um.get("input_tokens") or um.get("prompt_tokens") or 0
                ),
                completion_tokens=int(
                    um.get("output_tokens") or um.get("completion_tokens") or 0
                ),
                total_tokens=(
                    int(um.get("total_tokens") or 0) if "total_tokens" in um else None
                ),
            )
        elif "token_usage" in result and isinstance(result["token_usage"], dict):
            tu = result["token_usage"]
            usage.add(
                prompt_tokens=int(
                    tu.get("prompt_tokens") or tu.get("input_tokens") or 0
                ),
                completion_tokens=int(
                    tu.get("completion_tokens") or tu.get("output_tokens") or 0
                ),
                total_tokens=(
                    int(tu.get("total_tokens") or 0) if "total_tokens" in tu else None
                ),
            )
        elif "usage" in result and isinstance(result["usage"], dict):
            u = result["usage"]
            usage.add(
                prompt_tokens=int(u.get("prompt_tokens") or u.get("input_tokens") or 0),
                completion_tokens=int(
                    u.get("completion_tokens") or u.get("output_tokens") or 0
                ),
                total_tokens=(
                    int(u.get("total_tokens") or 0) if "total_tokens" in u else None
                ),
            )
    elif isinstance(result, list):
        messages = result
    elif hasattr(result, "usage_metadata") or hasattr(result, "response_metadata"):
        messages = [result]

    for msg in messages:
        has_extracted_usage = False
        if hasattr(msg, "usage_metadata") and msg.usage_metadata:
            um = msg.usage_metadata
            if isinstance(um, dict):
                p = int(um.get("input_tokens") or um.get("prompt_tokens") or 0)
                c = int(um.get("output_tokens") or um.get("completion_tokens") or 0)
                t = int(um.get("total_tokens") or (p + c))
                usage.add(prompt_tokens=p, completion_tokens=c, total_tokens=t)
                has_extracted_usage = True

        if (
            not has_extracted_usage
            and hasattr(msg, "response_metadata")
            and msg.response_metadata
        ):
            rm = msg.response_metadata
            if (
                isinstance(rm, dict)
                and "token_usage" in rm
                and isinstance(rm["token_usage"], dict)
            ):
                tu = rm["token_usage"]
                p = int(tu.get("prompt_tokens") or tu.get("input_tokens") or 0)
                c = int(tu.get("completion_tokens") or tu.get("output_tokens") or 0)
                t = int(tu.get("total_tokens") or (p + c))
                usage.add(prompt_tokens=p, completion_tokens=c, total_tokens=t)

    return usage


@dataclass
class StepExecution:
    name: str
    index: int
    status: StepStatus = StepStatus.PENDING
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    duration_seconds: Optional[float] = None
    token_usage: TokenUsage = field(default_factory=TokenUsage)
    metadata: Dict[str, Any] = field(default_factory=dict)
    error_category: Optional[str] = None
    error_message: Optional[str] = None
    diagnostic_hint: Optional[str] = None
    raw_output_snippet: Optional[str] = None

    @property
    def prompt_tokens(self) -> int:
        return self.token_usage.prompt_tokens if self.token_usage else 0

    @property
    def completion_tokens(self) -> int:
        return self.token_usage.completion_tokens if self.token_usage else 0

    @property
    def total_tokens(self) -> int:
        return self.token_usage.total_tokens if self.token_usage else 0

    def set_token_usage(
        self,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        total_tokens: Optional[int] = None,
    ) -> None:
        if self.token_usage is None:
            self.token_usage = TokenUsage()
        self.token_usage.prompt_tokens = prompt_tokens
        self.token_usage.completion_tokens = completion_tokens
        self.token_usage.total_tokens = (
            total_tokens
            if total_tokens is not None
            else (prompt_tokens + completion_tokens)
        )

    def start(
        self,
        metadata: Optional[Dict[str, Any]] = None,
        token_usage: Optional[Union[TokenUsage, Dict[str, Any]]] = None,
    ) -> None:
        self.start_time = time.time()
        self.status = StepStatus.RUNNING
        if metadata:
            self.metadata.update(metadata)
        if token_usage:
            if isinstance(token_usage, dict):
                self.token_usage = TokenUsage.from_dict(token_usage)
            elif isinstance(token_usage, TokenUsage):
                self.token_usage = token_usage

    def complete(
        self,
        metadata: Optional[Dict[str, Any]] = None,
        token_usage: Optional[Union[TokenUsage, Dict[str, Any]]] = None,
    ) -> None:
        self.end_time = time.time()
        if self.start_time is not None:
            self.duration_seconds = round(self.end_time - self.start_time, 3)
        self.status = StepStatus.COMPLETED
        if metadata:
            self.metadata.update(metadata)
        if token_usage:
            if isinstance(token_usage, dict):
                self.token_usage = TokenUsage.from_dict(token_usage)
            elif isinstance(token_usage, TokenUsage):
                self.token_usage = token_usage

    def fail(
        self,
        error_message: str,
        error_category: Optional[str] = None,
        diagnostic_hint: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        raw_output_snippet: Optional[str] = None,
        token_usage: Optional[Union[TokenUsage, Dict[str, Any]]] = None,
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
        if token_usage:
            if isinstance(token_usage, dict):
                self.token_usage = TokenUsage.from_dict(token_usage)
            elif isinstance(token_usage, TokenUsage):
                self.token_usage = token_usage

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
    total_token_usage: TokenUsage = field(default_factory=TokenUsage)
    success: bool = False
    steps: List[StepExecution] = field(default_factory=list)
    failed_step: Optional[StepExecution] = None
    error_summary: Optional[str] = None

    @property
    def prompt_tokens(self) -> int:
        return self.total_token_usage.prompt_tokens if self.total_token_usage else 0

    @property
    def completion_tokens(self) -> int:
        return self.total_token_usage.completion_tokens if self.total_token_usage else 0

    @property
    def total_tokens(self) -> int:
        return self.total_token_usage.total_tokens if self.total_token_usage else 0

    def calculate_token_usage(self) -> TokenUsage:
        prompt = sum(s.prompt_tokens for s in self.steps)
        completion = sum(s.completion_tokens for s in self.steps)
        total = sum(s.total_tokens for s in self.steps)
        self.total_token_usage = TokenUsage(
            prompt_tokens=prompt,
            completion_tokens=completion,
            total_tokens=total if total > 0 else (prompt + completion),
        )
        return self.total_token_usage

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

        # Automatically calculate aggregated token usage across all steps
        self.calculate_token_usage()

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
        token_header_info = ""
        if self.total_tokens > 0:
            token_header_info = f" | {self.total_tokens:,} tokens"

        header_status = (
            f"{green}SUCCESS{reset}" if self.success else f"{red}FAILED{reset}"
        )

        lines = [
            f"┌── Trace: {bold}{self.agent_name}{reset} [{header_status}] Target: '{self.target_identifier}' ({total_dur}{token_header_info}) ──",
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
                if step.total_tokens > 0:
                    lines.append(
                        f"│     {cyan}• Tokens: {step.total_tokens:,} (Prompt: {step.prompt_tokens:,} | Completion: {step.completion_tokens:,}){reset}"
                    )
                for k, v in step.metadata.items():
                    if k != "skip_reason" and k not in (
                        "prompt_tokens",
                        "completion_tokens",
                        "total_tokens",
                    ):
                        lines.append(f"│     {dim}• {k}: {v}{reset}")
            elif step.status == StepStatus.FAILED:
                icon = f"{red}[✖]{reset}"
                status_text = f"Step {step.index}: {step.name}{dur_str} - {bold}{red}FAILED{reset}"
                lines.append(f"│ {icon} {status_text}")
                if step.total_tokens > 0:
                    lines.append(
                        f"│     {cyan}• Tokens: {step.total_tokens:,} (Prompt: {step.prompt_tokens:,} | Completion: {step.completion_tokens:,}){reset}"
                    )
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
                    if k not in (
                        "prompt_tokens",
                        "completion_tokens",
                        "total_tokens",
                    ):
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

        if self.total_tokens > 0:
            lines.append(
                f"│ {bold}Total Usage: {self.total_tokens:,} tokens (Prompt: {self.prompt_tokens:,}, Completion: {self.completion_tokens:,}){reset}"
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
            "total_tokens": self.total_tokens,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_token_usage": (
                self.total_token_usage.to_dict() if self.total_token_usage else None
            ),
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
                    "token_usage": (s.token_usage.to_dict() if s.token_usage else None),
                    "prompt_tokens": s.prompt_tokens,
                    "completion_tokens": s.completion_tokens,
                    "total_tokens": s.total_tokens,
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
        token_usage_raw = data.get("total_token_usage") or {
            "prompt_tokens": data.get("prompt_tokens", 0),
            "completion_tokens": data.get("completion_tokens", 0),
            "total_tokens": data.get("total_tokens", 0),
        }
        trace = cls(
            agent_name=data.get("agent_name", "UnknownAgent"),
            target_identifier=data.get("target_identifier", "unknown_target"),
            start_time=data.get("start_time", 0.0),
            end_time=data.get("end_time"),
            duration_seconds=data.get("duration_seconds"),
            total_token_usage=TokenUsage.from_dict(token_usage_raw),
            success=data.get("success", False),
            error_summary=data.get("error_summary"),
        )
        steps = []
        for s_data in data.get("steps", []):
            try:
                status = StepStatus(s_data.get("status", "PENDING"))
            except Exception:
                status = StepStatus.PENDING
            s_token_raw = s_data.get("token_usage") or {
                "prompt_tokens": s_data.get("prompt_tokens", 0),
                "completion_tokens": s_data.get("completion_tokens", 0),
                "total_tokens": s_data.get("total_tokens", 0),
            }
            step = StepExecution(
                name=s_data.get("name", "UnknownStep"),
                index=s_data.get("index", len(steps) + 1),
                status=status,
                duration_seconds=s_data.get("duration_seconds"),
                token_usage=TokenUsage.from_dict(s_token_raw),
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
        if trace.total_token_usage.is_empty and any(
            not s.token_usage.is_empty for s in steps
        ):
            trace.calculate_token_usage()
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
        self,
        name: str,
        metadata: Optional[Dict[str, Any]] = None,
        token_usage: Optional[Union[TokenUsage, Dict[str, Any]]] = None,
    ) -> StepExecution:
        step = self._get_or_create_step(name)
        step.start(metadata=metadata, token_usage=token_usage)
        return step

    def complete_step(
        self,
        name: str,
        metadata: Optional[Dict[str, Any]] = None,
        token_usage: Optional[Union[TokenUsage, Dict[str, Any]]] = None,
    ) -> None:
        step = self._get_or_create_step(name)
        step.complete(metadata=metadata, token_usage=token_usage)

    def fail_step(
        self,
        name: str,
        error: Union[Exception, str],
        error_category: Optional[str] = None,
        diagnostic_hint: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        raw_output_snippet: Optional[str] = None,
        token_usage: Optional[Union[TokenUsage, Dict[str, Any]]] = None,
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
            token_usage=token_usage,
        )
        self.trace.failed_step = step
        self.trace.finish(
            success=False, error_summary=f"Step '{name}' failed: {error_msg}"
        )

    def record_step_token_usage(
        self,
        name: str,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        total_tokens: Optional[int] = None,
    ) -> None:
        step = self._get_or_create_step(name)
        step.set_token_usage(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
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
    def step(
        self,
        name: str,
        metadata: Optional[Dict[str, Any]] = None,
        token_usage: Optional[Union[TokenUsage, Dict[str, Any]]] = None,
    ):
        """
        Convenience context manager for executing and tracking a step.
        """
        step = self.start_step(name, metadata=metadata, token_usage=token_usage)
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
