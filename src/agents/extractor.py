from utils import handle_validation_error
import asyncio
from typing import Optional, List
import logging
from langchain_core.tools import BaseTool
from langchain.agents.middleware import ToolCallLimitMiddleware
from langchain.agents import create_agent
from pydantic import ValidationError, BaseModel, Field
from langchain_openai import ChatOpenAI


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
    os_distribution_or_edition: Optional[str] = Field(
        default="",
        description="The target OS distribution/edition extracted from the exploit details, e.g., 'ubuntu', 'debian', '10', '11', 'server 2019'. Leave empty if not mentioned or generic.",
    )
    os_version_or_release: Optional[str] = Field(
        default="",
        description="The target OS version/release/service pack, e.g., '20.04 lts', '22.04', 'sp1', '22h2', '1909'. Leave empty if not mentioned or generic.",
    )
    os_architecture: Optional[str] = Field(
        default="",
        description="The target OS CPU architecture, strictly formatted as '32-bit' or '64-bit'. Leave empty if not mentioned or generic.",
    )


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
            parsed_content = result["structured_response"]

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
