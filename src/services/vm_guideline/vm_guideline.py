import logging
from models.domain import VMGuidelineStatus
from repositories import VMGuidelineRepository
from typing import List, Optional
from .base import VMGuidelineService
from models import VMGuideline, VMGuidelineRecord


class DefaultVMGuidelineService(VMGuidelineService):
    """
    Default implementation of the VMGuidelineService interface.
    """

    def __init__(
        self,
        guide_repo: VMGuidelineRepository,
    ):
        self.guide_repo = guide_repo
        self._logger = logging.getLogger(self.__class__.__name__)

    def store_vm_guideline(self, vm_guideline: VMGuideline) -> None:
        record = VMGuidelineRecord(
            id=vm_guideline.id,
            path=vm_guideline.path,
            guideline=vm_guideline.guideline,
            status=vm_guideline.status.value,
            platform=vm_guideline.platform,
        )
        self.guide_repo.store_vm_guideline(record)

    def get_vm_guideline(self, guideline_id: int) -> Optional[VMGuideline]:
        record = self.guide_repo.get_vm_guideline(guideline_id)
        if record and record.status != VMGuidelineStatus.REJECTED.value:
            self._logger.info(
                f"Retrieved cached guideline from database (status: {record.status}) for ID {guideline_id}"
            )
            return VMGuideline.from_record(record)
        return None

    def get_vm_guideline_by_path(self, msf_path: str) -> List[VMGuideline]:
        records = self.guide_repo.get_vm_guideline_by_path(msf_path)
        results = []
        for record in records:
            if record.status != VMGuidelineStatus.REJECTED.value:
                results.append(VMGuideline.from_record(record))
        if results:
            self._logger.info(
                f"Retrieved {len(results)} cached guidelines from database for path {msf_path}"
            )
        return results

    def get_unverified_guidelines(self) -> List[VMGuideline]:
        records = self.guide_repo.get_unverified_guidelines()
        return [VMGuideline.from_record(r) for r in records]

    def update_guideline_status(
        self, msf_path: str, status: str, guideline_text: Optional[str] = None
    ) -> None:
        self.guide_repo.update_guideline_status(msf_path, status, guideline_text)
