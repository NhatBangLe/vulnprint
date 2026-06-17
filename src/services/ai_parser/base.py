try:
    from src.models import VulnerabilityTarget
except ImportError:
    from models import VulnerabilityTarget
from abc import ABC, abstractmethod


class VulnerabilityMetadataExtractor(ABC):
    """
    Abstract base class defining the interface for extracting target metadata
    from unstructured vulnerability/exploit descriptions.
    """

    @abstractmethod
    def extract_metadata(
        self, description_text: str, documentation_text: str = ""
    ) -> VulnerabilityTarget:
        """
        Analyzes description text and extracts structured details (software name,
        vulnerable versions, required configurations).
        """
        pass
