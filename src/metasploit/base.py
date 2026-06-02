from abc import ABC, abstractmethod
from typing import List

try:
    from src.models import MetasploitModuleDetails
except ImportError:
    from models import MetasploitModuleDetails


class MetasploitService(ABC):
    """
    Abstract base class defining the interface for Metasploit operations.
    """

    @abstractmethod
    def connect(self) -> None:
        """
        Initializes and establishes the connection to the Metasploit RPC server.
        """
        pass

    @abstractmethod
    def search_modules(self, search_string: str) -> List[str]:
        """
        Queries Metasploit's module database for exploits matching the search_string.
        """
        pass

    @abstractmethod
    def get_module_details(self, module_path: str) -> MetasploitModuleDetails:
        """
        Retrieves description and CVE references for a given module path.
        """
        pass
