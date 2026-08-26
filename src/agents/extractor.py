from utils import (
    format_validation_error_details,
    classify_llm_exception,
    AgentExecutionError,
    AgentPreconditionError,
    AgentLLMInvocationError,
    AgentResponseParsingError,
    AgentSchemaValidationError,
    AgentStepTracker,
    AgentExecutionTrace,
    AgentResult,
    extract_token_usage_from_result,
)
from typing import Optional, List, Literal
import logging
from langchain_core.tools import BaseTool
from langchain.agents.middleware import ToolCallLimitMiddleware
from langchain.agents import create_agent
from pydantic import ValidationError, BaseModel, Field
from langchain_openrouter import ChatOpenRouter


class OperatingSystemTarget(BaseModel):
    platform: Literal[
        "windows",
        "linux",
        "osx",
        "macos",
        "solaris",
        "netware",
        "android",
        "ios",
        "unix",
    ] = Field(
        description="The target OS platform. MUST be one of the specified general values (e.g. 'windows', 'linux').",
    )
    os_distribution_or_edition: Literal[
        "",
        "windows 2000",
        "windows xp",
        "windows vista",
        "windows 7",
        "windows 8",
        "windows 8.1",
        "windows 10",
        "windows 11",
        "windows server",
        "ubuntu",
        "debian",
        "centos",
        "redhat",
        "aix",
    ] = Field(
        default="",
        description="The target OS distribution/edition. MUST be one of the specified general values (e.g. 'windows 7', 'ubuntu'), or empty if generic/unknown.",
    )
    os_version_or_release: str = Field(
        default="",
        description="The target OS version/release. MUST be strictly formatted as a single specific version and optional build (e.g., '10.0', '10.0.19041', '10.0 build 17763', '22h2 build 19045', '20.04'). Do not include distribution/edition name, comments, version ranges, alternative versions (do not use 'or', 'and', or commas), or other text.",
        pattern=r"^(?:[vV]?\d+[a-zA-Z0-9.]*(?:\s+[Bb]uild\s+[a-zA-Z0-9.-]+)?|)$",
    )
    os_architecture: Literal["", "32-bit", "64-bit"] = Field(
        default="",
        description="The target OS CPU architecture, strictly formatted as '32-bit' or '64-bit'. Leave empty if not mentioned or generic.",
    )


class VulnerabilityTarget(BaseModel):
    id: Optional[int] = None
    software_name: str = Field(
        ..., description="Normalized generic name of the application"
    )
    vulnerable_versions: List[str] = Field(
        default_factory=list,
        description="Explicit version number array, e.g., ['9.0.30']",
    )
    required_configs: List[str] = Field(
        default_factory=list,
        description="Explicit application environment flags, e.g., ['AJP connector enabled']",
    )
    os_target: OperatingSystemTarget = Field(
        ...,
        description="The target Operating System and CPU architecture details.",
    )

    @property
    def platform(self) -> str:
        return self.os_target.platform

    @property
    def os_distribution_or_edition(self) -> str:
        return self.os_target.os_distribution_or_edition

    @property
    def os_version_or_release(self) -> str:
        return self.os_target.os_version_or_release

    @property
    def os_architecture(self) -> str:
        return self.os_target.os_architecture


EXPECTED_EXTRACTOR_STEPS = [
    "Input Validation & Preconditions",
    "Prompt & Context Construction",
    "Model & Tool Invocation",
    "Structured Response Extraction",
    "Schema Validation & Domain Construction",
]


class VulnerabilityTargetExtractorAgent:
    def __init__(
        self,
        ai_base_url: str,
        ai_api_key: str,
        ai_model: str,
        tools: Optional[List[BaseTool]] = None,
        max_tool_calls: Optional[int] = None,
        temperature: Optional[float] = None,
    ):
        self.ai_base_url = ai_base_url
        self.ai_api_key = ai_api_key
        self.ai_model = ai_model
        self.temperature = temperature

        self.max_tool_calls = max_tool_calls
        self.tools = tools

        middleware = (
            [ToolCallLimitMiddleware(run_limit=self.max_tool_calls)]
            if self.max_tool_calls is not None
            else []
        )

        self.agent = create_agent(
            name="Vulnerability Target Extractor Agent",
            model=ChatOpenRouter(
                base_url=self.ai_base_url,
                api_key=self.ai_api_key,
                model=self.ai_model,
                temperature=self.temperature,
            ),
            middleware=middleware,
            tools=self.tools,
            system_prompt=(
                "You are an expert open-source cyber threat intelligence extractor. "
                "Analyze the given exploit text block. Extract the primary software package target name, "
                "its explicit vulnerable version identifiers, specific environment rules, and target Operating System "
                "specifications (platform, distribution/edition, version/release name, architecture). "
                "If multiple target Operating System versions/releases are mentioned, you MUST pick only one (the primary or most specific one)."
            ),
            response_format=VulnerabilityTarget,
        )
        self._logger = logging.getLogger(self.__class__.__name__)
        self.last_trace: Optional[AgentExecutionTrace] = None

    async def extract_with_trace(
        self,
        description: str,
        documentation: str = "",
        cves: Optional[List[str]] = None,
        msf_path: Optional[str] = None,
        msf_module_name: Optional[str] = None,
        target_platforms: Optional[List[str]] = None,
        raise_on_error: bool = False,
    ) -> AgentResult[VulnerabilityTarget]:
        """
        Executes metadata extraction with complete step-by-step traceability.
        Returns an AgentResult containing data, full execution trace, and any error.
        """
        target_id = msf_path or msf_module_name or "unknown_target"
        tracker = AgentStepTracker(
            agent_name=self.__class__.__name__,
            target_identifier=target_id,
            expected_steps=EXPECTED_EXTRACTOR_STEPS,
        )
        self.last_trace = tracker.trace

        # Step 1: Input Validation & Preconditions
        current_step = EXPECTED_EXTRACTOR_STEPS[0]
        tracker.start_step(
            current_step,
            metadata={
                "has_description": bool(description and description.strip()),
                "has_documentation": bool(documentation and documentation.strip()),
                "cves_count": len(cves) if cves else 0,
                "target_platforms": target_platforms or [],
            },
        )
        combined_text = (description or "") + (documentation or "")
        if not combined_text.strip():
            err_msg = f"Exploit description and documentation are both empty for target '{target_id}'."
            hint = "Ensure the Metasploit module contains a non-empty description or documentation before extraction."
            tracker.fail_step(
                name=current_step,
                error=err_msg,
                error_category="AgentPreconditionError",
                diagnostic_hint=hint,
            )
            self._logger.error(tracker.trace.format_visual_box())
            error = AgentPreconditionError(
                message=err_msg,
                agent_name=self.__class__.__name__,
                step_name=current_step,
                step_index=1,
                diagnostic_hint=hint,
                trace=tracker.trace,
            )
            if raise_on_error:
                raise error
            return AgentResult(data=None, trace=tracker.trace, error=error)

        tracker.complete_step(current_step)

        # Step 2: Prompt & Context Construction
        current_step = EXPECTED_EXTRACTOR_STEPS[1]
        tracker.start_step(current_step)
        try:
            prompt_parts = [
                "Here is the provided exploit information, analyze and extract the relevant information."
            ]
            if msf_path:
                prompt_parts.append(f"Metasploit Path: {msf_path}")
            if msf_module_name:
                prompt_parts.append(f"Metasploit Module Name: {msf_module_name}")
            if cves:
                prompt_parts.append(f"Associated CVEs: {', '.join(cves)}")
            if target_platforms:
                prompt_parts.append(
                    f"Target Platforms (You MUST choose ONLY ONE based on the available options): {', '.join(target_platforms)}"
                )

            prompt_parts.append(f"\nExploit Description:\n{description}")
            prompt_parts.append(f"\nExploit Documentation:\n{documentation}")

            user_content = "\n".join(prompt_parts)
            tracker.complete_step(
                current_step,
                metadata={"prompt_length": len(user_content)},
            )
        except Exception as e:
            err_msg = f"Failed to construct extraction prompt: {e}"
            tracker.fail_step(
                name=current_step,
                error=e,
                error_category="AgentExecutionError",
                diagnostic_hint="Inspect input fields for non-serializable or malformed data.",
            )
            self._logger.error(tracker.trace.format_visual_box())
            error = AgentExecutionError(
                message=err_msg,
                agent_name=self.__class__.__name__,
                step_name=current_step,
                step_index=2,
                trace=tracker.trace,
            )
            if raise_on_error:
                raise error
            return AgentResult(data=None, trace=tracker.trace, error=error)

        # Step 3: Model & Tool Invocation
        current_step = EXPECTED_EXTRACTOR_STEPS[2]
        tracker.start_step(
            current_step,
            metadata={"ai_model": self.ai_model, "base_url": self.ai_base_url},
        )
        try:
            result = await self.agent.ainvoke(
                {"messages": [{"role": "user", "content": user_content}]},
            )
            step_usage = extract_token_usage_from_result(result)
            tracker.complete_step(
                current_step,
                metadata={
                    "response_keys": (
                        list(result.keys()) if isinstance(result, dict) else []
                    ),
                    "prompt_tokens": step_usage.prompt_tokens,
                    "completion_tokens": step_usage.completion_tokens,
                    "total_tokens": step_usage.total_tokens,
                },
                token_usage=step_usage,
            )
        except ValidationError as e:
            details = format_validation_error_details(e)
            hint = "The AI agent structured output violated Pydantic schema constraints during invocation."
            tracker.fail_step(
                name=current_step,
                error=details,
                error_category="AgentSchemaValidationError",
                diagnostic_hint=hint,
            )
            self._logger.error(tracker.trace.format_visual_box())
            error = AgentSchemaValidationError(
                message=details,
                agent_name=self.__class__.__name__,
                step_name=current_step,
                step_index=3,
                diagnostic_hint=hint,
                trace=tracker.trace,
            )
            if raise_on_error:
                raise error
            return AgentResult(data=None, trace=tracker.trace, error=error)
        except Exception as e:
            category, hint = classify_llm_exception(e)
            tracker.fail_step(
                name=current_step,
                error=e,
                error_category=category,
                diagnostic_hint=hint,
            )
            self._logger.error(tracker.trace.format_visual_box())
            error = AgentLLMInvocationError(
                message=str(e),
                agent_name=self.__class__.__name__,
                step_name=current_step,
                step_index=3,
                diagnostic_hint=hint,
                trace=tracker.trace,
            )
            if raise_on_error:
                raise error
            return AgentResult(data=None, trace=tracker.trace, error=error)

        # Step 4: Structured Response Extraction
        current_step = EXPECTED_EXTRACTOR_STEPS[3]
        tracker.start_step(current_step)
        parsed_content = (
            result.get("structured_response") if isinstance(result, dict) else None
        )
        if not parsed_content:
            raw_snippet = None
            if isinstance(result, dict) and "messages" in result:
                msgs = result["messages"]
                if msgs and hasattr(msgs[-1], "content"):
                    raw_snippet = str(msgs[-1].content)
                elif msgs and isinstance(msgs[-1], dict):
                    raw_snippet = str(msgs[-1].get("content", ""))

            err_msg = (
                f"Missing 'structured_response' key in agent output. Keys returned: "
                f"{list(result.keys()) if isinstance(result, dict) else type(result).__name__}."
            )
            hint = (
                "The model did not return structured schema data. Check if the model supports tool/structured outputs "
                "or if it outputted unstructured conversational text."
            )
            tracker.fail_step(
                name=current_step,
                error=err_msg,
                error_category="AgentResponseParsingError",
                diagnostic_hint=hint,
                raw_output_snippet=raw_snippet,
            )
            self._logger.error(tracker.trace.format_visual_box())
            error = AgentResponseParsingError(
                message=err_msg,
                agent_name=self.__class__.__name__,
                step_name=current_step,
                step_index=4,
                diagnostic_hint=hint,
                trace=tracker.trace,
            )
            if raise_on_error:
                raise error
            return AgentResult(data=None, trace=tracker.trace, error=error)

        tracker.complete_step(current_step)

        # Step 5: Schema Validation & Domain Construction
        current_step = EXPECTED_EXTRACTOR_STEPS[4]
        tracker.start_step(current_step)
        if not isinstance(parsed_content, VulnerabilityTarget):
            err_msg = f"Parsed output is not an instance of VulnerabilityTarget (received {type(parsed_content).__name__})."
            hint = "Ensure the agent response parser returns an instance of VulnerabilityTarget."
            tracker.fail_step(
                name=current_step,
                error=err_msg,
                error_category="AgentSchemaValidationError",
                diagnostic_hint=hint,
            )
            self._logger.error(tracker.trace.format_visual_box())
            error = AgentSchemaValidationError(
                message=err_msg,
                agent_name=self.__class__.__name__,
                step_name=current_step,
                step_index=5,
                diagnostic_hint=hint,
                trace=tracker.trace,
            )
            if raise_on_error:
                raise error
            return AgentResult(data=None, trace=tracker.trace, error=error)

        tracker.complete_step(
            current_step,
            metadata={
                "software_name": parsed_content.software_name,
                "platform": parsed_content.platform,
                "distribution": parsed_content.os_distribution_or_edition,
                "version": parsed_content.os_version_or_release,
                "architecture": parsed_content.os_architecture,
                "vulnerable_versions_count": len(parsed_content.vulnerable_versions),
            },
        )
        tracker.finish(success=True)

        return AgentResult(data=parsed_content, trace=tracker.trace, error=None)

    async def extract(
        self,
        description: str,
        documentation: str = "",
        cves: Optional[List[str]] = None,
        msf_path: Optional[str] = None,
        msf_module_name: Optional[str] = None,
        target_platforms: Optional[List[str]] = None,
        raise_on_error: bool = False,
    ) -> Optional[VulnerabilityTarget]:
        """
        Leverages the AI model to parse exploit description and documentation text, returning validated metadata.
        Maintains backward compatibility while preserving full step traceability in self.last_trace.
        """
        result = await self.extract_with_trace(
            description=description,
            documentation=documentation,
            cves=cves,
            msf_path=msf_path,
            msf_module_name=msf_module_name,
            target_platforms=target_platforms,
            raise_on_error=raise_on_error,
        )
        return result.data
