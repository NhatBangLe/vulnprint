import json
import logging
from openai import OpenAI


try:
    from src.models import ExploitDetails
    from src.ai_parser.base import VulnerabilityMetadataExtractor
except ImportError:
    from models import ExploitDetails
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
    ):
        self.base_url = base_url
        self.api_key = api_key
        self.model_name = model_name
        self._logger = logging.getLogger(self.__class__.__name__)

    def extract_metadata(self, description_text: str) -> ExploitDetails:
        """
        Leverages local SLM to parse exploit description text and returns validated metadata.
        """
        fallback_data = {
            "software_name": "Unknown",
            "vulnerable_versions": [],
            "required_configs": [],
        }

        if not description_text or not description_text.strip():
            return ExploitDetails.model_validate(fallback_data)

        try:
            # Instantiate client pointing to local server instance
            client = OpenAI(base_url=self.base_url, api_key=self.api_key)

            system_message = (
                "You are an expert open-source cyber threat intelligence parser. "
                "Analyze the given exploit text block. Extract the primary software package target name, "
                "its explicit vulnerable version identifiers, and specific environment rules. "
                "You must reply strictly with a raw JSON object containing the keys 'software_name', "
                "'vulnerable_versions', and 'required_configs'. Do not provide conversational text, "
                "headers, markdown wrapping, or commentary."
            )

            user_message = f"Exploit Text: {description_text}"

            # Request completions from the local engine
            response = client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": system_message},
                    {"role": "user", "content": user_message},
                ],
                response_format={"type": "json_object"},
                temperature=0.0,
            )

            raw_content = response.choices[0].message.content
            if not raw_content:
                raise ValueError("Empty response received from the local model.")

            # Strip potential markdown code fence markers (e.g. ```json ... ```)
            cleaned_content = raw_content.strip()
            if cleaned_content.startswith("```"):
                # strip start line
                lines = cleaned_content.splitlines()
                if lines[0].startswith("```"):
                    lines = lines[1:]
                if lines and lines[-1].startswith("```"):
                    lines = lines[:-1]
                cleaned_content = "\n".join(lines).strip()

            # Validate structure with Pydantic
            return ExploitDetails.model_validate_json(cleaned_content)
        except json.JSONDecodeError as jde:
            self._logger.error(f"JSON parsing failed on model response: {jde}")
            if "raw_content" in locals():
                self._logger.error(f"Raw response was: {raw_content}")
            return ExploitDetails.model_validate(fallback_data)
        except Exception as e:
            self._logger.error(f"Error during LLM analysis or Pydantic validation: {e}")
            return ExploitDetails.model_validate(fallback_data)
