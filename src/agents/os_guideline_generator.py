import logging
from typing import Optional
from services import MSFModuleService, SoftwareService
from models import OSGuideline, GuidelineStatus


# class OSGuidelineGeneratorResult(BaseModel):
#     os_guideline: str = Field(
#         ...,
#         description=(
#             "A detailed step-by-step Operating System Installation Guideline, including VM requirements, "
#             "download sources (if available), and OS setup steps in markdown format. "
#             "Crucially, this MUST NOT mention "
#             "the specific Metasploit module, target software, CVEs, or software-specific details, "
#             "as it will be re-used across other modules on the same platform."
#         ),
#     )


class OSGuidelineGeneratorAgent:
    def __init__(
        self,
        msf_service: MSFModuleService,
        soft_service: SoftwareService,
        # ai_base_url: str,
        # ai_api_key: str,
        # ai_model: str,
        # tools: Optional[List[BaseTool]] = None,
        # max_tool_calls: int = 5,
        # temperature: float = 0.4,
    ):
        self.msf_service = msf_service
        self.soft_service = soft_service

        # self.ai_base_url = ai_base_url
        # self.ai_api_key = ai_api_key
        # self.ai_model = ai_model

        # self.max_tool_calls = max_tool_calls
        # self.tools = tools

        # self.agent = create_agent(
        #     debug=True,
        #     name="OS Guideline Generator Agent",
        #     model=ChatOpenAI(
        #         base_url=self.ai_base_url,
        #         api_key=self.ai_api_key,
        #         model=self.ai_model,
        #         temperature=temperature,
        #     ),
        #     middleware=[ToolCallLimitMiddleware(run_limit=self.max_tool_calls)],
        #     tools=self.tools,
        #     system_prompt=(
        #         "You are an agentic cybersecurity lab setup engineer. "
        #         "Your goal is to search the web using the provided tools to locate operating system installation instructions "
        #         "and virtual machine setup steps for the specified target OS. "
        #         "Compile a highly practical Operating System installation guide (for base VM setup) in markdown format. "
        #         "Crucially, the OS guideline (os_guideline) must be completely generic for the OS and platform, and MUST NOT "
        #         "contain any references to the specific Metasploit module path, software name, version, or CVEs, so that it can be re-used."
        #         "DO NOT MENTION the software, CVEs or any software-specific details in the guideline."
        #     ),
        #     response_format=OSGuidelineGeneratorResult,
        # )
        self._logger = logging.getLogger(self.__class__.__name__)

    def generate(self, msf_path: str) -> Optional[OSGuideline]:
        # self._logger.info(
        #     f"Starting agentic OS guideline generation workflow for module: {msf_path}"
        # )

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

        try:
            return OSGuideline(
                guideline=f"Install the base operating system: {os_name}.",
                platform=software.platform,
                distribution=software.distribution,
                version=software.version,
                architecture=software.architecture,
                status=GuidelineStatus.VERIFIED,
            )
        except Exception as e:
            self._logger.error(f"Error during OS guideline generation: {e}")
            return None
