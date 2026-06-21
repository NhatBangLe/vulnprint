import logging
from typing import List, Optional, Tuple
from repositories import SoftwareGuidelineRepository
from .base import SoftwareGuidelineService
from models import (
    SoftwareGuideline,
    SoftwareGuidelineRecord,
    GuidelineStatus,
    GuidelineCoverageItem,
    VMGuidelineCoverageStats,
)


class DefaultSoftwareGuidelineService(SoftwareGuidelineService):
    """
    Default implementation of the SoftwareGuidelineService interface.
    """

    def __init__(self, sw_guide_repo: SoftwareGuidelineRepository):
        self.sw_guide_repo = sw_guide_repo
        self._logger = logging.getLogger(self.__class__.__name__)

    def store_software_guideline(
        self, software_guideline: SoftwareGuideline, path: str
    ) -> int:
        record = SoftwareGuidelineRecord(
            id=software_guideline.id,
            guideline=software_guideline.guideline,
            os_guideline_id=software_guideline.os_guideline_id,
            software_id=software_guideline.software_id,
            status=software_guideline.status.value,
        )
        return self.sw_guide_repo.store_software_guideline(record, path)

    def get_software_guideline(self, guideline_id: int) -> Optional[SoftwareGuideline]:
        record = self.sw_guide_repo.get_software_guideline(guideline_id)
        if record and record.status != GuidelineStatus.REJECTED.value:
            return SoftwareGuideline.from_record(record)
        return None

    def get_software_guidelines_by_path(self, msf_path: str) -> List[SoftwareGuideline]:
        records = self.sw_guide_repo.get_software_guidelines_by_path(msf_path)
        results = []
        for record in records:
            if record.status != GuidelineStatus.REJECTED.value:
                results.append(SoftwareGuideline.from_record(record))
        return results

    def get_unverified_guidelines(self) -> List[SoftwareGuideline]:
        records = self.sw_guide_repo.get_unverified_guidelines()
        return [SoftwareGuideline.from_record(r) for r in records]

    def update_guideline_status(
        self, msf_path: str, status: str, guideline_text: Optional[str] = None
    ) -> None:
        self.sw_guide_repo.update_guideline_status(msf_path, status, guideline_text)

    def link_guideline_to_module(self, msf_path: str, guideline_id: int) -> None:
        self.sw_guide_repo.link_guideline_to_module(msf_path, guideline_id)

    def find_all_potential_guidelines(
        self, platform: List[str], software_name: str, vulnerable_versions: List[str]
    ) -> List[Tuple[int, SoftwareGuideline]]:
        normalized_target_software = software_name.lower().strip()
        metadata_list = self.sw_guide_repo.get_guidelines_with_software_metadata()

        candidates = []
        for meta in metadata_list:
            if len(meta.associated_software_name) == 0:
                continue
            if (
                normalized_target_software
                != meta.associated_software_name.lower().strip()
            ):
                continue

            score = 0

            # 1. Platform score
            if platform and meta.associated_platforms:
                overlap = set(p.lower().strip() for p in platform) & set(
                    ap.lower().strip() for ap in meta.associated_platforms
                )
                if len(overlap) > 0:
                    score += 30
            elif len(platform) == 0 or len(meta.associated_platforms) == 0:
                score += 15

            # 2. Version score
            if vulnerable_versions and meta.associated_versions:
                overlap = set(v.lower().strip() for v in vulnerable_versions) & set(
                    av.lower().strip() for av in meta.associated_versions
                )
                if len(overlap) > 0:
                    score += 40
            elif len(vulnerable_versions) == 0 or len(meta.associated_versions) == 0:
                score += 20

            # Compatibility threshold check (50 points required)
            if score >= 50:
                guideline = self.get_software_guideline(meta.guideline_id)
                if guideline:
                    candidates.append((score, guideline))

        return candidates

    def get_guideline_coverage_stats(self) -> VMGuidelineCoverageStats:
        metadata_list = self.sw_guide_repo.get_guidelines_with_software_metadata()

        total_guidelines = len(metadata_list)
        total_coverage_count = 0
        items = []

        for meta in metadata_list:
            coverage_count = len(meta.module_paths)
            total_coverage_count += coverage_count
            items.append(
                GuidelineCoverageItem(
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

        return VMGuidelineCoverageStats(
            total_guidelines=total_guidelines,
            average_coverage=round(average_coverage, 2),
            guidelines=items,
        )
