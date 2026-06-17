from models.domain import VMGuidelineStatus
from search_agent import SearchAgent
from repositories import VMGuidelineRepository
from typing import List, Optional
from .base import VMGuidelineService
from models import VMGuideline, VMGuidelineRecord


class DefaultVMGuidelineService(VMGuidelineService):
    """
    Default implementation of the VMGuidelineService interface.
    """

    def __init__(self, guide_repo: VMGuidelineRepository, search_agent: SearchAgent):
        self.guide_repo = guide_repo
        self.search_agent = search_agent

    def store_vm_guideline(self, vm_guideline: VMGuideline) -> None:
        record = VMGuidelineRecord(
            path=vm_guideline.path,
            guideline=vm_guideline.guideline,
            status=vm_guideline.status.value,
        )
        self.guide_repo.store_vm_guideline(record)

    def get_vm_guideline(self, msf_path: str) -> Optional[VMGuideline]:
        record = self.guide_repo.get_vm_guideline(msf_path)
        if not record:
            return None
        if record.status != VMGuidelineStatus.REJECTED.value:
            self._logger.info(
                f"Retrieved cached guideline from database (status: {record.status}) for {msf_path}"
            )
            return VMGuideline.from_record(record)

        self._logger.warning(
            f"Guideline for {msf_path} is REJECTED in database. Regenerating..."
        )
        guideline_str = self.search_agent.search(msf_path)
        guideline = VMGuideline(path=msf_path, guideline=guideline_str)
        self.store_vm_guideline(guideline)
        return guideline

    def get_unverified_guidelines(self) -> List[VMGuideline]:
        records = self.guide_repo.get_unverified_guidelines()
        return [VMGuideline.from_record(r) for r in records]

    def update_guideline_status(
        self, msf_path: str, status: str, guideline_text: Optional[str] = None
    ) -> None:
        self.guide_repo.update_guideline_status(msf_path, status, guideline_text)
