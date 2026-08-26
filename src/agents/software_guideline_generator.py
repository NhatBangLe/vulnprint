import logging
from typing import Optional, List, TYPE_CHECKING
from pydantic import BaseModel, Field, ValidationError
from langchain_core.tools import BaseTool
from langchain_openrouter import ChatOpenRouter
from langchain.agents import create_agent
from langchain.agents.middleware import ToolCallLimitMiddleware
from models import SoftwareGuideline, GuidelineStatus
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

if TYPE_CHECKING:
    from services.msf_module import MSFModuleService
    from services.software import SoftwareService
    from services.os_guideline import OSGuidelineService


class SoftwareGuidelineGeneratorResult(BaseModel):
    software_guideline: str = Field(
        ...,
        description=(
            "A detailed step-by-step Software Installation Guideline for installing the vulnerable "
            "target software/version on the chosen OS in markdown format."
            "DO NOT MENTION the OS installation instructions in the guideline. "
            "JUST PROVIDE the software installation instructions and configurations."
        ),
    )


EXPECTED_SOFTWARE_GUIDELINE_STEPS = [
    "Entity Verification & Preconditions",
    "Context & Prompt Assembly",
    "Web Search & LLM Invocation",
    "Structured Response Extraction",
    "Guideline Domain Model Instantiation",
]


class SoftwareGuidelineGeneratorAgent:
    def __init__(
        self,
        msf_service: "MSFModuleService",
        soft_service: "SoftwareService",
        os_guide_service: "OSGuidelineService",
        ai_base_url: str,
        ai_api_key: str,
        ai_model: str,
        tools: Optional[List[BaseTool]] = None,
        max_tool_calls: Optional[int] = None,
        temperature: Optional[float] = None,
    ):
        self.msf_service = msf_service
        self.soft_service = soft_service
        self.os_guide_service = os_guide_service

        self.ai_base_url = ai_base_url
        self.ai_api_key = ai_api_key
        self.ai_model = ai_model

        self.max_tool_calls = max_tool_calls
        self.tools = tools

        middleware = (
            [ToolCallLimitMiddleware(run_limit=self.max_tool_calls)]
            if self.max_tool_calls is not None
            else []
        )

        self.agent = create_agent(
            name="Software Guideline Generator Agent",
            model=ChatOpenRouter(
                base_url=self.ai_base_url,
                api_key=self.ai_api_key,
                model=self.ai_model,
                temperature=temperature,
            ),
            middleware=middleware,
            tools=self.tools,
            system_prompt=(
                "You are an agentic cybersecurity lab setup engineer. "
                "Your goal is to search the web using the provided tools to locate installation instructions, "
                "vulnerable packages, and configuration steps for a specific software target on a chosen Operating System. "
                "Compile a highly practical, step-by-step Software Installation Guideline for installing and configuring the "
                "vulnerable target software/version on the chosen OS in markdown format."
                "DO NOT MENTION the OS installation instructions in the guideline. "
                "JUST PROVIDE the software installation instructions and configurations."
            ),
            response_format=SoftwareGuidelineGeneratorResult,
        )
        self._logger = logging.getLogger(self.__class__.__name__)
        self.last_trace: Optional[AgentExecutionTrace] = None

    async def generate_with_trace(
        self,
        msf_path: str,
        os_guideline_id: int,
        raise_on_error: bool = False,
    ) -> AgentResult[SoftwareGuideline]:
        """
        Executes software guideline generation with complete step-by-step traceability.
        Returns an AgentResult containing data, full execution trace, and any error.
        """
        tracker = AgentStepTracker(
            agent_name=self.__class__.__name__,
            target_identifier=f"{msf_path} (OS Guideline ID: {os_guideline_id})",
            expected_steps=EXPECTED_SOFTWARE_GUIDELINE_STEPS,
        )
        self.last_trace = tracker.trace

        self._logger.info(
            f"Starting agentic software guideline generation workflow for module: {msf_path} using OS guideline ID: {os_guideline_id}"
        )

        # Step 1: Entity Verification & Preconditions
        current_step = EXPECTED_SOFTWARE_GUIDELINE_STEPS[0]
        tracker.start_step(
            current_step,
            metadata={"msf_path": msf_path, "os_guideline_id": os_guideline_id},
        )

        msf_module = self.msf_service.get_module_by_path(msf_path)
        if not msf_module:
            err_msg = f"Metasploit module '{msf_path}' not found in database."
            hint = "Verify the module path or run module ingestion into the database first."
            tracker.fail_step(
                name="Entity Verification & Preconditions",
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

        software = self.soft_service.get_software_by_path(msf_path)
        if not software:
            err_msg = f"Software record not found in database for path: '{msf_path}'."
            hint = "Run vulnerability target extraction to create the software record before generating software guidelines."
            tracker.fail_step(
                name="Entity Verification & Preconditions",
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

        os_guideline = self.os_guide_service.get_os_guideline_by_id(os_guideline_id)
        if not os_guideline:
            err_msg = f"OS Guideline ID {os_guideline_id} not found in database."
            hint = "Ensure the referenced OS guideline exists in the database or generate a new OS guideline first."
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

        tracker.complete_step(
            current_step,
            metadata={
                "software_name": software.name,
                "os_name": os_guideline.os_name,
                "software_id": software.id,
            },
        )

        # Step 2: Context & Prompt Assembly
        current_step = EXPECTED_SOFTWARE_GUIDELINE_STEPS[1]
        tracker.start_step(current_step)
        try:
            cves_str = ", ".join(software.cves) if software.cves else "None"
            versions_str = (
                ", ".join(software.vulnerable_versions)
                if software.vulnerable_versions
                else "Unknown"
            )
            configs_str = (
                "; ".join(software.required_configs)
                if software.required_configs
                else "None"
            )

            user_content = (
                f"Generate a step-by-step Software Installation Guideline to set up the vulnerable software on the following base Operating System:\n"
                f"Base OS Name: {os_guideline.os_name}\n"
                f"Base OS Setup Instructions:\n{os_guideline.guideline}\n\n"
                f"Target Metasploit Module Path: {msf_module.path}\n"
                f"Module Description: {msf_module.description}\n"
                f"Associated CVEs: {cves_str}\n"
                f"Software Target Name: {software.name}\n"
                f"Vulnerable Versions: {versions_str}\n"
                f"Required Configurations: {configs_str}\n"
                "IMPORTANT: DO NOT MENTION the OS installation instructions in the guideline. "
                "JUST PROVIDE the software installation instructions and configurations.\n\n"
                "Try considering the testing section in the detailed documentation if available for "
                "guidance on the software installation.\n\n"
                "HERE IS THE METASPLOIT DETAILED DOCUMENTATION:"
                f"{msf_module.documentation}"
            )
            tracker.complete_step(
                current_step,
                metadata={
                    "prompt_length": len(user_content),
                    "cves": cves_str,
                    "versions": versions_str,
                },
            )
        except Exception as e:
            err_msg = f"Failed to assemble context/prompt for software guideline generator: {e}"
            tracker.fail_step(
                name=current_step,
                error=e,
                error_category="AgentExecutionError",
                diagnostic_hint="Verify that software and OS guideline fields contain valid text data.",
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

        # Step 3: Web Search & LLM Invocation
        current_step = EXPECTED_SOFTWARE_GUIDELINE_STEPS[2]
        tracker.start_step(
            current_step,
            metadata={
                "ai_model": self.ai_model,
                "base_url": self.ai_base_url,
                "tools_available": len(self.tools) if self.tools else 0,
            },
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
        current_step = EXPECTED_SOFTWARE_GUIDELINE_STEPS[3]
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
                f"Missing 'structured_response' in agent output. Keys returned: "
                f"{list(result.keys()) if isinstance(result, dict) else type(result).__name__}."
            )
            hint = (
                "The agent failed to produce structured SoftwareGuidelineGeneratorResult output. "
                "Check if MCP search tools returned empty results or if model output was truncated."
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

        if not isinstance(parsed_content, SoftwareGuidelineGeneratorResult):
            err_msg = f"Parsed output is not an instance of SoftwareGuidelineGeneratorResult (received {type(parsed_content).__name__})."
            hint = (
                "Ensure response format is correctly configured on the LangChain agent."
            )
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
                step_index=4,
                diagnostic_hint=hint,
                trace=tracker.trace,
            )
            if raise_on_error:
                raise error
            return AgentResult(data=None, trace=tracker.trace, error=error)

        tracker.complete_step(current_step)

        # Step 5: Guideline Domain Model Instantiation
        current_step = EXPECTED_SOFTWARE_GUIDELINE_STEPS[4]
        tracker.start_step(current_step)
        try:
            guideline = SoftwareGuideline(
                guideline=parsed_content.software_guideline,
                os_guideline_id=os_guideline_id,
                software_id=software.id,
                status=GuidelineStatus.UNVERIFIED,
                path=msf_path,
            )
            tracker.complete_step(
                current_step,
                metadata={
                    "guideline_length": len(parsed_content.software_guideline),
                    "status": guideline.status.value,
                },
            )
            tracker.finish(success=True)
            return AgentResult(data=guideline, trace=tracker.trace, error=None)
        except ValidationError as e:
            details = format_validation_error_details(e)
            tracker.fail_step(
                name=current_step,
                error=details,
                error_category="AgentSchemaValidationError",
                diagnostic_hint="SoftwareGuideline domain model constraints were violated.",
            )
            self._logger.error(tracker.trace.format_visual_box())
            error = AgentSchemaValidationError(
                message=details,
                agent_name=self.__class__.__name__,
                step_name=current_step,
                step_index=5,
                trace=tracker.trace,
            )
            if raise_on_error:
                raise error
            return AgentResult(data=None, trace=tracker.trace, error=error)
        except Exception as e:
            err_msg = f"Error during SoftwareGuideline creation: {e}"
            tracker.fail_step(
                name=current_step,
                error=e,
                error_category="AgentExecutionError",
            )
            self._logger.error(tracker.trace.format_visual_box())
            error = AgentExecutionError(
                message=err_msg,
                agent_name=self.__class__.__name__,
                step_name=current_step,
                step_index=5,
                trace=tracker.trace,
            )
            if raise_on_error:
                raise error
            return AgentResult(data=None, trace=tracker.trace, error=error)

    async def generate(
        self,
        msf_path: str,
        os_guideline_id: int,
        raise_on_error: bool = False,
    ) -> Optional[SoftwareGuideline]:
        """
        Synchronously communicates with tools, lets the LLM execute search queries,
        and returns the software guideline based on the base OS installation.
        Maintains backward compatibility while preserving full step traceability in self.last_trace.
        """
        result = await self.generate_with_trace(
            msf_path=msf_path,
            os_guideline_id=os_guideline_id,
            raise_on_error=raise_on_error,
        )
        return result.data
