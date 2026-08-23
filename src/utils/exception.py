from typing import Optional, Dict, Any, Tuple, TYPE_CHECKING
import logging
from pydantic import ValidationError

if TYPE_CHECKING:
    from .agent_tracer import AgentExecutionTrace


class AgentExecutionError(Exception):
    """
    Base exception raised during generative agent execution failures.
    Contains full step context, root cause, and diagnostic hints.
    """

    def __init__(
        self,
        message: str,
        agent_name: str = "Agent",
        step_name: str = "Unknown",
        step_index: Optional[int] = None,
        diagnostic_hint: Optional[str] = None,
        trace: Optional["AgentExecutionTrace"] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.message = message
        self.agent_name = agent_name
        self.step_name = step_name
        self.step_index = step_index
        self.diagnostic_hint = diagnostic_hint
        self.trace = trace
        self.details = details or {}

    def __str__(self) -> str:
        step_info = (
            f"Step {self.step_index} ('{self.step_name}')"
            if self.step_index is not None
            else f"Step '{self.step_name}'"
        )
        hint = f" (Hint: {self.diagnostic_hint})" if self.diagnostic_hint else ""
        return f"[{self.agent_name}] {step_info} failed: {self.message}{hint}"


class AgentPreconditionError(AgentExecutionError):
    """Raised when required input, context, or database prerequisite is missing."""

    pass


class AgentLLMInvocationError(AgentExecutionError):
    """Raised when communication with the LLM API fails (e.g. rate limit, auth, network)."""

    pass


class AgentToolCallError(AgentExecutionError):
    """Raised when tool execution (e.g. MCP search) fails or tool limit is exceeded."""

    pass


class AgentResponseParsingError(AgentExecutionError):
    """Raised when LLM output cannot be extracted or parsed into structured format."""

    pass


class AgentSchemaValidationError(AgentExecutionError):
    """Raised when structured response fails domain/schema validation rules."""

    pass


class AgentPersistenceError(AgentExecutionError):
    """Raised when saving generated guidelines/records to database fails."""

    pass


def classify_llm_exception(e: Exception) -> Tuple[str, str]:
    """
    Analyzes an exception from LLM/LangChain/Tool execution to classify its category
    and supply a clear diagnostic hint.
    """
    error_str = str(e).lower()
    error_type = type(e).__name__

    if "429" in error_str or "rate limit" in error_str or "quota" in error_str:
        return (
            "AgentLLMInvocationError",
            "Rate limit or quota exceeded on AI Provider. Consider lowering concurrency, switching AI_MODEL, or checking provider balance.",
        )
    elif "401" in error_str or "unauthorized" in error_str or "api key" in error_str:
        return (
            "AgentLLMInvocationError",
            "Authentication failed. Verify AI_API_KEY and AI_BASE_URL configuration.",
        )
    elif "timeout" in error_str or "timed out" in error_str:
        return (
            "AgentLLMInvocationError",
            "Network timeout while waiting for LLM or tool response. Check network connectivity or increase request timeout.",
        )
    elif (
        "connection" in error_str
        or "refused" in error_str
        or "connecterror" in error_str
    ):
        return (
            "AgentLLMInvocationError",
            "Connection error to AI API or MCP Server. Verify MCP server (e.g. localhost:8000) is running and endpoint is reachable.",
        )
    elif "run_limit" in error_str or "toolcalllimit" in error_str:
        return (
            "AgentToolCallError",
            "Tool call limit reached during agent reasoning. Increase MCP_MAX_TOOL_CALLS or refine search instructions.",
        )
    elif "validationerror" in error_type.lower() or "validation error" in error_str:
        return (
            "AgentSchemaValidationError",
            "Model response failed Pydantic schema validation. Review model output against expected schema constraints.",
        )
    elif "json" in error_str or "parse" in error_str:
        return (
            "AgentResponseParsingError",
            "Model response could not be parsed as valid structured JSON. The model may have returned unstructured conversational text.",
        )

    return (
        "AgentExecutionError",
        "Inspect the underlying error message and stack trace for further details.",
    )


def format_validation_error_details(e: ValidationError) -> str:
    """
    Formats Pydantic ValidationError into a compact, human-readable diagnostic string.
    """
    lines = [f"Validation failed with {len(e.errors())} error(s):"]
    for err in e.errors():
        loc = " -> ".join(str(x) for x in err.get("loc", []))
        msg = err.get("msg", "Invalid value")
        err_type = err.get("type", "unknown")
        input_val = err.get("input", "")
        lines.append(
            f"  • Field '{loc}': {msg} (type={err_type}, input={repr(input_val)})"
        )
    return "\n".join(lines)


def handle_validation_error(
    e: ValidationError, logger: Optional[logging.Logger] = None
):
    details = format_validation_error_details(e)
    if logger:
        logger.error(details)
    else:
        print(details)
