from abc import ABC, abstractmethod
from models import MinimalVMGuidelinesCoverage


class VMGuidelineService(ABC):
    """
    Interface for VM guidelines service.
    """

    @abstractmethod
    def get_minimal_vm_guidelines_coverage(
        self, total_msf_modules: int
    ) -> MinimalVMGuidelinesCoverage:
        """
        Calculates the minimal set of VM guidelines to cover all coverable Metasploit modules.
        """
        pass
