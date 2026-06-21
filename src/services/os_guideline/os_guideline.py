import logging
from typing import Optional
from repositories import OSGuidelineRepository
from .base import OSGuidelineService
from models import OSGuideline, OSGuidelineRecord, GuidelineStatus


class DefaultOSGuidelineService(OSGuidelineService):
    """
    Default implementation of the OSGuidelineService interface.
    """

    def __init__(self, os_guide_repo: OSGuidelineRepository):
        self.os_guide_repo = os_guide_repo
        self._logger = logging.getLogger(self.__class__.__name__)

    def store_os_guideline(self, os_guideline: OSGuideline) -> int:
        record = OSGuidelineRecord(
            id=os_guideline.id,
            os_name=os_guideline.os_name,
            guideline=os_guideline.guideline,
            platform=os_guideline.platform,
            status=os_guideline.status.value,
        )
        return self.os_guide_repo.store_os_guideline(record)

    def get_os_guideline(self, guideline_id: int) -> Optional[OSGuideline]:
        record = self.os_guide_repo.get_os_guideline(guideline_id)
        if record and record.status != GuidelineStatus.REJECTED.value:
            return OSGuideline.from_record(record)
        return None

    def get_os_guideline_by_name(self, os_name: str) -> Optional[OSGuideline]:
        record = self.os_guide_repo.get_os_guideline_by_name(os_name)
        if record and record.status != GuidelineStatus.REJECTED.value:
            return OSGuideline.from_record(record)
        return None
