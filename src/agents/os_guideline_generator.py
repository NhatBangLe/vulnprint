import logging
import asyncio
from typing import Optional, List
from pydantic import BaseModel, Field, ValidationError
from langchain_core.tools import BaseTool
from langchain_openai import ChatOpenAI
from langchain.agents import create_agent
from langchain.agents.middleware import ToolCallLimitMiddleware
from services import MSFModuleService, SoftwareService
from models import OSGuideline, GuidelineStatus
from utils import handle_validation_error


class OSGuidelineGeneratorResult(BaseModel):
    os_guideline: str = Field(
        ...,
        description="A detailed step-by-step Operating System Installation Guideline, including VM requirements, download sources, and OS setup steps in markdown format. Crucially, this MUST NOT mention the specific Metasploit module, target software, CVEs, or software-specific details, as it will be re-used across other modules on the same platform.",
    )


class OSGuidelineGeneratorAgent:
    def __init__(
        self,
        msf_service: MSFModuleService,
        soft_service: SoftwareService,
        ai_base_url: str,
        ai_api_key: str,
        ai_model: str,
        tools: Optional[List[BaseTool]] = None,
        max_tool_calls: int = 5,
        temperature: float = 0.4,
    ):
        self.msf_service = msf_service
        self.soft_service = soft_service

        self.ai_base_url = ai_base_url
        self.ai_api_key = ai_api_key
        self.ai_model = ai_model

        self.max_tool_calls = max_tool_calls
        self.tools = tools

        self.agent = create_agent(
            name="OS Guideline Generator Agent",
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
                "Your goal is to search the web using the provided tools to locate operating system installation instructions "
                "and virtual machine setup steps for the specified target OS. "
                "Compile a highly practical Operating System installation guide (for base VM setup) in markdown format. "
                "Crucially, the OS guideline (os_guideline) must be completely generic for the OS and platform, and MUST NOT "
                "contain any references to the specific Metasploit module path, software name, version, or CVEs, so that it can be re-used."
            ),
            response_format=OSGuidelineGeneratorResult,
        )
        self._logger = logging.getLogger(self.__class__.__name__)

    def generate(self, msf_path: str) -> Optional[OSGuideline]:
        """
        Synchronously communicates with tools, lets the LLM execute search queries,
        and returns the generic OS guideline.
        """
        self._logger.info(
            f"Starting agentic OS guideline generation workflow for module: {msf_path}"
        )

        msf_module = self.msf_service.get_module_by_path(msf_path)
        if not msf_module:
            self._logger.error(f"Module not found in database: {msf_path}")
            return None

        software = self.soft_service.get_software_by_path(msf_path)
        if not software:
            self._logger.error(f"Software not found in database: {msf_path}")
            return None

        # Reconstruct OS name from software target system properties
        parts = []
        if software.distribution:
            parts.append(software.distribution)
        else:
            parts.append(software.platform)
        if software.version:
            parts.append(software.version)
        if software.architecture:
            parts.append(f"({software.architecture})")
        os_name = " ".join(parts)

        software_name = software.name
        cves_str = ", ".join(software.cves) if software.cves else "None"
        versions_str = (
            ", ".join(software.vulnerable_versions)
            if software.vulnerable_versions
            else "Unknown"
        )

        try:
            user_content = (
                f"Identify and generate a generic Virtual Machine OS setup guideline for this Operating System target:\n"
                f"Target OS: {os_name}\n"
                f"Platform: {software.platform}\n"
                f"Module Path: {msf_module.path}\n"
                f"Description: {msf_module.description}\n"
                f"Target Software: {software_name}\n"
                f"Associated CVEs: {cves_str}\n"
                f"Vulnerable Versions: {versions_str}\n"
            )

            result = asyncio.run(
                self.agent.ainvoke(
                    {"messages": [{"role": "user", "content": user_content}]},
                )
            )
            parsed_content = result["structured_response"]

            if not isinstance(parsed_content, OSGuidelineGeneratorResult):
                self._logger.warning(
                    "Cannot parse OS Guideline Generator result from LLM output."
                )
                return None

            return OSGuideline(
                # os_name=os_name,
                guideline=parsed_content.os_guideline,
                platform=software.platform,
                distribution=software.distribution,
                version=software.version,
                architecture=software.architecture,
                status=GuidelineStatus.UNVERIFIED,
            )
        except ValidationError as e:
            handle_validation_error(e, self._logger)
            return None
        except Exception as e:
            self._logger.error(f"Error during OS agent invocation: {e}")
            return None
