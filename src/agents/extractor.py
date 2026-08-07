from utils import handle_validation_error
import re
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

        self.agent = create_agent(
            name="Vulnerability Target Extractor Agent",
            model=ChatOpenRouter(
                base_url=self.ai_base_url,
                api_key=self.ai_api_key,
                model=self.ai_model,
                temperature=self.temperature,
            ),
            middleware=[ToolCallLimitMiddleware(run_limit=self.max_tool_calls)],
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

    async def extract(
        self,
        description: str,
        documentation: str = "",
        cves: Optional[List[str]] = None,
        msf_path: Optional[str] = None,
        msf_module_name: Optional[str] = None,
        target_platforms: Optional[List[str]] = None,
    ) -> Optional[VulnerabilityTarget]:
        """
        Leverages the AI model to parse exploit description and documentation text, returning validated metadata.
        """
        # Check if we have any input text
        combined_text = (description or "") + (documentation or "")
        if not combined_text.strip():
            return None

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
            result = await self.agent.ainvoke(
                {"messages": [{"role": "user", "content": user_content}]},
            )
            parsed_content = result.get("structured_response")
            if not parsed_content:
                self._logger.warning(
                    f"Result keys from LLM execution: {list(result.keys())}. 'structured_response' is missing."
                )
                return None

            if not isinstance(parsed_content, VulnerabilityTarget):
                self._logger.warning(
                    "Cannot parse vulnerability target information from LLM output."
                )
                return None
            return parsed_content
        except ValidationError as e:
            handle_validation_error(e, self._logger)
            return None
        except Exception as e:
            self._logger.error(f"Error during LLM analysis: {e}")
            return None
