import logging
from typing import List, Optional
from repositories import VMGuidelineRepository
from .base import VMGuidelineService
from models import (
    VMGuideline,
    VMGuidelineRecord,
    VMGuidelineStatus,
    GuidelineCoverageItem,
    VMGuidelineCoverageStats,
)


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

    def link_guideline_to_module(self, msf_path: str, guideline_id: int) -> None:
        self.guide_repo.link_guideline_to_module(msf_path, guideline_id)

    def find_suitable_guideline(
        self, platform: List[str], software_name: str, vulnerable_versions: List[str]
    ) -> Optional[VMGuideline]:
        if not software_name:
            return None

        normalized_target_software = software_name.lower().strip()
        metadata_list = self.guide_repo.get_guidelines_with_software_metadata()
        best_candidate = None
        best_score = -1

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
            if score < 50:
                continue

            # Tie-breaking logic
            if score > best_score:
                best_score = score
                best_candidate = meta
            elif score == best_score:
                # 1. Prefer VERIFIED over other statuses
                current_is_verified = meta.status == VMGuidelineStatus.VERIFIED.value
                best_is_verified = (
                    (best_candidate.status == VMGuidelineStatus.VERIFIED.value)
                    if best_candidate
                    else False
                )

                if current_is_verified and not best_is_verified:
                    best_candidate = meta
                elif current_is_verified == best_is_verified:
                    # 2. Prefer guideline with more coverage
                    if len(meta.module_paths) > len(best_candidate.module_paths):
                        best_candidate = meta

        if best_candidate:
            self._logger.info(
                f"Found suitable guideline (ID: {best_candidate.guideline_id}) covering software "
                f"'{best_candidate.associated_software_name}' with score {best_score}"
            )
            return self.get_vm_guideline(best_candidate.guideline_id)

        return None

    def get_guideline_coverage_stats(self) -> VMGuidelineCoverageStats:
        metadata_list = self.guide_repo.get_guidelines_with_software_metadata()

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
