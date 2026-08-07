import logging
from typing import Optional, List
from pydantic import BaseModel, Field, ValidationError
from langchain_core.tools import BaseTool
from langchain_openrouter import ChatOpenRouter
from langchain.agents import create_agent
from langchain.agents.middleware import ToolCallLimitMiddleware
from services import MSFModuleService, SoftwareService, OSGuidelineService
from models import SoftwareGuideline, GuidelineStatus
from utils import handle_validation_error


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


class SoftwareGuidelineGeneratorAgent:
    def __init__(
        self,
        msf_service: MSFModuleService,
        soft_service: SoftwareService,
        os_guide_service: OSGuidelineService,
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

        self.agent = create_agent(
            name="Software Guideline Generator Agent",
            model=ChatOpenRouter(
                base_url=self.ai_base_url,
                api_key=self.ai_api_key,
                model=self.ai_model,
                temperature=temperature,
            ),
            middleware=[ToolCallLimitMiddleware(run_limit=self.max_tool_calls)],
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

    async def generate(
        self, msf_path: str, os_guideline_id: int
    ) -> Optional[SoftwareGuideline]:
        """
        Synchronously communicates with tools, lets the LLM execute search queries,
        and returns the software guideline based on the base OS installation.
        """
        self._logger.info(
            f"Starting agentic software guideline generation workflow for module: {msf_path} using OS guideline ID: {os_guideline_id}"
        )

        msf_module = self.msf_service.get_module_by_path(msf_path)
        if not msf_module:
            self._logger.error(f"Module not found in database: {msf_path}")
            return None

        software = self.soft_service.get_software_by_path(msf_path)
        if not software:
            self._logger.error(f"Software not found in database: {msf_path}")
            return None

        os_guideline = self.os_guide_service.get_os_guideline_by_id(os_guideline_id)
        if not os_guideline:
            self._logger.error(
                f"OS Guideline ID {os_guideline_id} not found in database."
            )
            return None

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

        try:
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
                "JUST PROVIDE the software installation instructions and configurations"
            )

            result = await self.agent.ainvoke(
                {"messages": [{"role": "user", "content": user_content}]},
            )
            parsed_content = result.get("structured_response")
            if not parsed_content:
                self._logger.warning(
                    f"Result keys from LLM execution: {list(result.keys())}. 'structured_response' is missing."
                )
                return None

            if not isinstance(parsed_content, SoftwareGuidelineGeneratorResult):
                self._logger.warning(
                    "Cannot parse Software Guideline Generator result from LLM output."
                )
                return None

            return SoftwareGuideline(
                guideline=parsed_content.software_guideline,
                os_guideline_id=os_guideline_id,
                software_id=software.id,
                status=GuidelineStatus.UNVERIFIED,
                path=msf_path,
            )
        except ValidationError as e:
            handle_validation_error(e, self._logger)
            return None
        except Exception as e:
            self._logger.error(f"Error during software agent invocation: {e}")
            return None
