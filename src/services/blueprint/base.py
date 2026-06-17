from abc import ABC, abstractmethod
from typing import Optional


class BlueprintService(ABC):
    """
    Abstract base class defining the interface for generating lab blueprint manuals.
    """

    @abstractmethod
    def generate_blueprint(self, msf_path: str) -> Optional[str]:
        """
        Generates a blueprint manual for the given Metasploit path.
        Returns the absolute/relative filepath to the generated manual, or None.
        """
        pass
