from typing import Optional
from repositories import OSGuidelineRepository
from .base import OSGuidelineService
from models import OSGuideline, OSGuidelineRecord


class DefaultOSGuidelineService(OSGuidelineService):
    """
    Default implementation of the OSGuidelineService interface.
    """

    def __init__(self, os_guide_repo: OSGuidelineRepository):
        self.os_guide_repo = os_guide_repo

    def store_os_guideline(self, os_guideline: OSGuideline) -> int:
        record = OSGuidelineRecord(
            id=os_guideline.id,
            os_name=os_guideline.os_name,
            guideline=os_guideline.guideline,
            platform=os_guideline.platform,
            status=os_guideline.status.value,
        )
        return self.os_guide_repo.save(record)

    def get_os_guideline_by_id(self, guideline_id: int) -> Optional[OSGuideline]:
        record = self.os_guide_repo.get_by_id(guideline_id)
        return OSGuideline.from_record(record)

    def get_os_guideline_by_name(self, os_name: str) -> Optional[OSGuideline]:
        record = self.os_guide_repo.get_by_name(os_name)
        return OSGuideline.from_record(record)
