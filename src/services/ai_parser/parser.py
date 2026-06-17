from pydantic import ValidationError
import logging
from langchain_openai import ChatOpenAI
from models import VulnerabilityTarget
from .base import VulnerabilityMetadataExtractor


class LLMVulnerabilityMetadataExtractor(VulnerabilityMetadataExtractor):
    """
    Concrete implementation of VulnerabilityMetadataExtractor leveraging local SLM
    via an OpenAI-compatible API to parse exploit descriptions.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:11434/v1",
        api_key: str = "local-engine",
        model_name: str = "llama3",
        temperature: float = 0.0,
    ):
        self.base_url = base_url
        self.api_key = api_key
        self.model_name = model_name
        self.temperature = temperature
        self.model = ChatOpenAI(
            base_url=self.base_url,
            api_key=self.api_key,
            model=self.model_name,
            temperature=self.temperature,
        )
        self._logger = logging.getLogger(self.__class__.__name__)

    def extract_metadata(
        self, description_text: str, documentation_text: str = ""
    ) -> VulnerabilityTarget:
        """
        Leverages local SLM to parse exploit description and documentation text, returning validated metadata.
        """
        fallback_data = {
            "software_name": "Unknown",
            "vulnerable_versions": [],
            "required_configs": [],
        }

        # Check if we have any input text
        combined_text = (description_text or "") + (documentation_text or "")
        if not combined_text.strip():
            return VulnerabilityTarget.model_validate(fallback_data)

        try:
            system_message = (
                "You are an expert open-source cyber threat intelligence parser. "
                "Analyze the given exploit text block. Extract the primary software package target name, "
                "its explicit vulnerable version identifiers, and specific environment rules. "
            )

            user_message = (
                "Here is the provided exploit information, analyze and extract the relevant information."
                f"\nExploit Description:\n{description_text}"
                f"\n\nExploit Documentation:\n{documentation_text}"
            )

            structured_llm = self.model.with_structured_output(VulnerabilityTarget)
            parsed_content = structured_llm.invoke(
                [
                    {"role": "system", "content": system_message},
                    {"role": "user", "content": user_message},
                ]
            )

            if parsed_content is None:
                self._logger.warning(
                    "No parsed data received from the model. Return fallback data."
                )
                return VulnerabilityTarget.model_validate(fallback_data)
            return parsed_content
        except ValidationError as e:
            self._logger.error("Pydantic Validation Failed!")

            # Loop through errors to see exactly what broke and what the text looked like
            for error in e.errors():
                self._logger.error(
                    "Error Message: {msg}."
                    "\nError Location: {loc}, "
                    "Error Type: {type}, "
                    "Input:\n{input}".format(**error)
                )
            return VulnerabilityTarget.model_validate(fallback_data)
        except Exception as e:
            self._logger.error(f"Error during LLM analysis: {e}")
            return VulnerabilityTarget.model_validate(fallback_data)
