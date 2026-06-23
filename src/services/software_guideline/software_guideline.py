import logging
from typing import List, Optional
from repositories import SoftwareGuidelineRepository
from .base import SoftwareGuidelineService
from models import (
    SoftwareGuideline,
    SoftwareGuidelineRecord,
    GuidelineStatus,
    SoftwareGuidelineCoverageItem,
    SoftwareGuidelineCoverageStats,
)


class DefaultSoftwareGuidelineService(SoftwareGuidelineService):
    """
    Default implementation of the SoftwareGuidelineService interface.
    """

    def __init__(self, sw_guide_repo: SoftwareGuidelineRepository):
        self.sw_guide_repo = sw_guide_repo
        self._logger = logging.getLogger(self.__class__.__name__)

    def store_software_guideline(
        self, software_guideline: SoftwareGuideline
    ) -> Optional[int]:
        record = SoftwareGuidelineRecord(
            id=software_guideline.id,
            path=software_guideline.path,
            guideline=software_guideline.guideline,
            os_guideline_id=software_guideline.os_guideline_id,
            software_id=software_guideline.software_id,
            status=software_guideline.status.value,
        )
        return self.sw_guide_repo.save(record)

    def get_software_guideline(self, guideline_id: int) -> Optional[SoftwareGuideline]:
        record = self.sw_guide_repo.get_by_id(guideline_id)
        if record and record.status != GuidelineStatus.REJECTED.value:
            return SoftwareGuideline.from_record(record)
        return None

    def get_software_guidelines_by_path(self, msf_path: str) -> List[SoftwareGuideline]:
        records = self.sw_guide_repo.get_by_path(msf_path)
        results = []
        for record in records:
            if record.status != GuidelineStatus.REJECTED.value:
                results.append(SoftwareGuideline.from_record(record))
        return results

    def get_unverified_guidelines(self) -> List[SoftwareGuideline]:
        records = self.sw_guide_repo.get_unverified_guidelines()
        return [SoftwareGuideline.from_record(r) for r in records]

    def update_guideline_status(
        self,
        msf_path: str,
        status: GuidelineStatus,
        guideline_text: Optional[str] = None,
    ) -> None:
        guideline_id = self.sw_guide_repo.exists_by_path(msf_path)
        if not guideline_id:
            raise Exception(f"Could not find software guideline linked to: {msf_path}")

        record = self.sw_guide_repo.get_by_id(guideline_id)
        if not record:
            raise Exception(
                f"Software guideline with ID {guideline_id} not found/retrievable."
            )

        record.status = status.value
        if guideline_text is not None:
            record.guideline = guideline_text

        self.sw_guide_repo.save(record)

    def link_guideline_to_module(self, msf_path: str, guideline_id: int) -> None:
        self.sw_guide_repo.link_guideline_to_module(msf_path, guideline_id)

    def get_software_guidelines_by_os_id(self, os_guideline_id: int) -> List[SoftwareGuideline]:
        records = self.sw_guide_repo.get_by_os_guideline_id(os_guideline_id)
        results = []
        for record in records:
            if record.status != GuidelineStatus.REJECTED.value:
                results.append(SoftwareGuideline.from_record(record))
        return results

    def get_guideline_coverage_stats(self) -> SoftwareGuidelineCoverageStats:
        metadata_list = self.sw_guide_repo.get_guidelines_with_software_metadata()

        total_guidelines = len(metadata_list)
        total_coverage_count = 0
        items = []

        for meta in metadata_list:
            coverage_count = len(meta.module_paths)
            total_coverage_count += coverage_count
            items.append(
                SoftwareGuidelineCoverageItem(
                    guideline_id=meta.guideline_id,
                    software_name=meta.associated_software_name or "Unknown Software",
                    status=meta.status,
                    modules_covered=meta.module_paths,
                    coverage_count=coverage_count,
                )
            )

        # Sort by coverage count descending, and then by software name
        items.sort(key=lambda x: (-x.coverage_count, x.software_name))

        average_coverage = (
            (total_coverage_count / total_guidelines) if total_guidelines > 0 else 0.0
        )

        return SoftwareGuidelineCoverageStats(
            total_guidelines=total_guidelines,
            average_coverage=round(average_coverage, 2),
            guidelines=items,
        )
