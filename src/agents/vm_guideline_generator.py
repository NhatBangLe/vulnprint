import logging
import asyncio
from typing import Optional, List, Tuple
from pydantic import BaseModel, Field, ValidationError
from langchain_core.tools import BaseTool
from langchain_openai import ChatOpenAI
from langchain.agents import create_agent
from langchain.agents.middleware import ToolCallLimitMiddleware
from services import MSFModuleService, VulnerabilityTargetService
from models import OSGuideline, SoftwareGuideline, GuidelineStatus


class VMGuidelineGeneratorResult(BaseModel):
    platform: str = Field(
        ...,
        description="The target platform platform name, e.g. Linux, Windows.",
    )
    os_name: str = Field(
        ...,
        description="The specific name and version of the Operating System chosen, e.g. 'Ubuntu 24.04 LTS', 'Windows 10'.",
    )
    os_guideline: str = Field(
        ...,
        description="A detailed step-by-step Operating System Installation Guideline, including VM requirements, download sources, and OS setup steps.",
    )
    software_guideline: str = Field(
        ...,
        description="A detailed step-by-step Software Installation Guideline for installing the vulnerable target software/version on the chosen OS.",
    )


class VMGuidelineGeneratorAgent:
    def __init__(
        self,
        msf_service: MSFModuleService,
        vuln_service: VulnerabilityTargetService,
        ai_base_url: str,
        ai_api_key: str,
        ai_model: str,
        tools: Optional[List[BaseTool]] = None,
        max_tool_calls: int = 5,
        temperature: float = 0.4,
    ):
        self.msf_service = msf_service
        self.vuln_service = vuln_service

        self.ai_base_url = ai_base_url
        self.ai_api_key = ai_api_key
        self.ai_model = ai_model

        self.max_tool_calls = max_tool_calls
        self.tools = tools

        self.agent = create_agent(
            name="VM Guideline Generator Agent",
            model=ChatOpenAI(
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
                "vulnerable packages, and virtual machine setups for a specific Metasploit module target. "
                "You must locate where to download the legacy target, install steps, and system prerequisites. "
                "Use the tools iteratively as needed up to the limit. Once you have enough information, "
                "compile a highly practical Operating System installation guide (for base VM setup) and "
                "a separate Software installation guide (for setting up the vulnerable package) for this module target."
            ),
            response_format=VMGuidelineGeneratorResult,
        )
        self._logger = logging.getLogger(self.__class__.__name__)

    def generate(
        self, msf_path: str
    ) -> Optional[Tuple[OSGuideline, SoftwareGuideline]]:
        """
        Synchronously communicates with tools, lets the LLM execute search queries,
        and returns the synthesized guidelines.
        """
        self._logger.info(
            f"Starting agentic guideline generation workflow for module: {msf_path}"
        )

        msf_details = self.msf_service.get_module_details(msf_path)
        if not msf_details:
            self._logger.error(f"Module not found in database: {msf_path}")
            return None

        vuln_target = self.vuln_service.get_vulnerability_target(msf_path)
        if not vuln_target:
            self._logger.error(
                f"Vulnerability target not found in database: {msf_path}"
            )
            return None

        cves_str = ", ".join(msf_details.cves) if msf_details.cves else "None"
        versions_str = (
            ", ".join(vuln_target.vulnerable_versions)
            if vuln_target.vulnerable_versions
            else "Unknown"
        )
        configs_str = (
            "; ".join(vuln_target.required_configs)
            if vuln_target.required_configs
            else "None"
        )

        try:
            user_content = (
                f"Generate a Virtual Machine OS and Software Installation Guideline for this Metasploit module:\n"
                f"Module Path: {msf_details.module_name}\n"
                f"Associated CVEs: {cves_str}\n"
                f"Software Target: {vuln_target.software_name}\n"
                f"Vulnerable Versions: {versions_str}\n"
                f"Required Configurations: {configs_str}\n"
                f"Description: {msf_details.description}\n"
                f"Available target platforms: {msf_details.platform}\n"
            )

            result = asyncio.run(
                self.agent.ainvoke(
                    {"messages": [{"role": "user", "content": user_content}]},
                )
            )
            parsed_content = result["structured_response"]

            if not isinstance(parsed_content, VMGuidelineGeneratorResult):
                self._logger.warning(
                    "Cannot parse VM Guideline Generator result from LLM output."
                )
                return None
            return (
                OSGuideline(
                    os_name=parsed_content.os_name,
                    guideline=parsed_content.os_guideline,
                    platform=parsed_content.platform,
                    status=GuidelineStatus.UNVERIFIED,
                ),
                SoftwareGuideline(
                    guideline=parsed_content.software_guideline,
                    os_guideline_id=0,
                    software_id=0,
                    status=GuidelineStatus.UNVERIFIED,
                ),
            )
        except ValidationError as e:
            self._logger.error(f"Validation error: {e}")
            for error in e.errors():
                self._logger.error(
                    "Error Message: {msg}."
                    "\nError Location: {loc}, "
                    "Error Type: {type}, "
                    "Input:\n{input}".format(**error)
                )
            return None
        except Exception as e:
            self._logger.error(f"Error during agent invocation: {e}")
            return None
