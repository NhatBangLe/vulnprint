from pydantic import BaseModel
from langchain_core.tools import BaseTool
import logging
from typing import Optional
from langchain_openai import ChatOpenAI
from langchain.agents import create_agent
from langchain.agents.middleware import ToolCallLimitMiddleware
from services import MSFModuleService, VulnerabilityTargetService


class SearchResult(BaseModel):
    url: str
    title: str
    snippet: str
    description: str
    categories: list[str] | None = None
    tags: list[str] | None = None


class SearchAgent:
    """
    Agent coordinates verified/unverified VM Guideline searches.
    Uses MCPSearchClient to query external search tools and LLM to structure outputs.
    """

    def __init__(
        self,
        msf_service: MSFModuleService,
        vuln_service: VulnerabilityTargetService,
        ai_base_url: str,
        ai_api_key: str,
        ai_model: str,
        tools: list[BaseTool] | None = None,
        max_tool_calls: int = 5,
        temperature: float = 0.5,
    ):
        self.msf_service = msf_service
        self.vuln_service = vuln_service

        self.ai_base_url = ai_base_url
        self.ai_api_key = ai_api_key
        self.ai_model = ai_model

        self.max_tool_calls = max_tool_calls
        self.tools = tools

        self.agent = create_agent(
            name="Search Agent",
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
                "compile a highly practical, step-by-step VM Installation Guideline for this module target."
            ),
        )
        self._logger = logging.getLogger(self.__class__.__name__)

    def search(self, msf_path: str) -> Optional[str]:
        """
        Synchronously communicates with tools, lets the LLM execute search queries,
        and returns the synthesized guideline.
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

        user_content = (
            f"Generate a Virtual Machine Installation Guideline for this Metasploit module:\n"
            f"Module Path: {msf_details.module_name}\n"
            f"Associated CVEs: {cves_str}\n"
            f"Software Target: {vuln_target.software_name}\n"
            f"Vulnerable Versions: {versions_str}\n"
            f"Required Configurations: {configs_str}\n"
            f"Description: {msf_details.description}\n"
        )

        result = self.agent.invoke(
            {"messages": [{"role": "user", "content": user_content}]},
        )
        return result
