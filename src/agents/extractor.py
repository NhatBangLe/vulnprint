from utils import handle_validation_error
import asyncio
import re
from typing import Optional, List, Literal
import logging
from langchain_core.tools import BaseTool
from langchain.agents.middleware import ToolCallLimitMiddleware
from langchain.agents import create_agent
from pydantic import ValidationError, BaseModel, Field, field_validator
from langchain_openai import ChatOpenAI


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
        description="The target OS platform. Must be one of the specified general values (e.g. 'windows', 'linux').",
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
        "linux",
        "ubuntu",
        "debian",
        "centos",
        "redhat",
        "aix",
    ] = Field(
        default="",
        description="The target OS distribution/edition. Must be one of the specified general values (e.g. 'windows 7', 'ubuntu'), or empty if generic/unknown.",
    )
    os_version_or_release: str = Field(
        default="",
        description="The target OS version/release. MUST be strictly formatted as a string of numbers (digits and decimals/periods only, e.g., '20.04', '7.2', '10', '11'). Do not include text, words, ranges, or comparison operators.",
    )
    os_architecture: Literal["", "32-bit", "64-bit"] = Field(
        default="",
        description="The target OS CPU architecture, strictly formatted as '32-bit' or '64-bit'. Leave empty if not mentioned or generic.",
    )

    @field_validator("os_version_or_release", mode="before")
    @classmethod
    def validate_version_numeric(cls, v: any) -> str:
        if not v:
            return ""
        if not isinstance(v, str):
            v = str(v)
        # Extract the first contiguous block of numbers and decimals
        match = re.search(r"\d+(\.\d+)*", v)
        if match:
            return match.group(0)
        return ""


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
        max_tool_calls: int = 5,
        temperature: float = 0.4,
    ):
        self.ai_base_url = ai_base_url
        self.ai_api_key = ai_api_key
        self.ai_model = ai_model
        self.temperature = temperature

        self.max_tool_calls = max_tool_calls
        self.tools = tools

        self.agent = create_agent(
            name="Vulnerability Target Extractor Agent",
            model=ChatOpenAI(
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
                "specifications (distribution/edition, version/release name, architecture) if specified."
            ),
            response_format=VulnerabilityTarget,
        )
        self._logger = logging.getLogger(self.__class__.__name__)

    def extract(
        self, description: str, documentation: str = ""
    ) -> Optional[VulnerabilityTarget]:
        """
        Leverages the AI model to parse exploit description and documentation text, returning validated metadata.
        """
        # Check if we have any input text
        combined_text = (description or "") + (documentation or "")
        if not combined_text.strip():
            return None

        try:
            user_content = (
                "Here is the provided exploit information, analyze and extract the relevant information."
                f"\nExploit Description:\n{description}"
                f"\n\nExploit Documentation:\n{documentation}"
            )
            result = asyncio.run(
                self.agent.ainvoke(
                    {"messages": [{"role": "user", "content": user_content}]},
                )
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
