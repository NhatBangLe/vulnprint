try:
    from src.models import ExploitDetails
except ImportError:
    from models import ExploitDetails
from abc import ABC, abstractmethod


class VulnerabilityMetadataExtractor(ABC):
    """
    Abstract base class defining the interface for extracting target metadata
    from unstructured vulnerability/exploit descriptions.
    """

    @abstractmethod
    def extract_metadata(self, description_text: str) -> ExploitDetails:
        """
        Analyzes description text and extracts structured details (software name,
        vulnerable versions, required configurations).
        """
        pass
