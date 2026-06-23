from typing import List, Optional, Tuple
from repositories import OSGuidelineRepository, TargetSystemRepository
from .base import OSGuidelineService
from models import (
    OSGuideline,
    OSGuidelineRecord,
    TargetSystemRecord,
    GuidelineStatus,
    OSGuidelineCoverageStats,
    OSGuidelineCoverageItem,
)


class DefaultOSGuidelineService(OSGuidelineService):
    """
    Default implementation of the OSGuidelineService interface.
    """

    def __init__(
        self,
        os_guide_repo: OSGuidelineRepository,
        target_system_repo: TargetSystemRepository,
    ):
        self.os_guide_repo = os_guide_repo
        self.target_system_repo = target_system_repo

    def store_os_guideline(self, os_guideline: OSGuideline) -> int:
        # Save TargetSystem details using attributes directly from os_guideline
        target_system_id = self.target_system_repo.save(
            TargetSystemRecord(
                platform=os_guideline.platform,
                distribution=os_guideline.distribution,
                version=os_guideline.version,
                architecture=os_guideline.architecture,
            )
        )

        record = OSGuidelineRecord(
            id=os_guideline.id,
            guideline=os_guideline.guideline,
            target_system_id=target_system_id,
            status=os_guideline.status.value,
        )
        return self.os_guide_repo.save(record)

    def get_os_guideline_by_id(self, guideline_id: int) -> Optional[OSGuideline]:
        record = self.os_guide_repo.get_by_id(guideline_id)
        if record:
            return OSGuideline.from_record(record)
        return None

    def find_all_potential_guidelines(
        self, target_system_id: Optional[int], platforms: List[str] = None
    ) -> List[Tuple[int, OSGuideline]]:
        target_system = None
        if target_system_id:
            target_system = self.target_system_repo.get_by_id(target_system_id)

        all_records = self.os_guide_repo.get_all_guidelines()
        candidates = []

        for record in all_records:
            if record.status == GuidelineStatus.REJECTED.value:
                continue

            score = 0
            if target_system:
                # Score against target system components
                if (
                    record.platform.lower().strip()
                    != target_system.platform.lower().strip()
                ):
                    continue
                score += 30

                t_dist = target_system.distribution.lower().strip()
                r_dist = record.distribution.lower().strip()
                if t_dist:
                    if t_dist == r_dist:
                        score += 30
                else:
                    score += 15

                t_ver = target_system.version.lower().strip()
                r_ver = record.version.lower().strip()
                if t_ver:
                    if t_ver == r_ver:
                        score += 20
                else:
                    score += 10

                t_arch = target_system.architecture.lower().strip()
                r_arch = record.architecture.lower().strip()
                if t_arch:
                    if t_arch == r_arch:
                        score += 20
                else:
                    score += 10
            else:
                if not platforms:
                    continue
                req_plats = [p.lower().strip() for p in platforms]
                if record.platform.lower().strip() in req_plats:
                    score += 30
                    score += 15
                    score += 10
                    score += 10

            if score > 0:
                candidates.append((score, OSGuideline.from_record(record)))

        return candidates

    def get_os_guideline_coverage_stats(self) -> OSGuidelineCoverageStats:
        records = self.os_guide_repo.get_os_guideline_coverage_stats()
        total_guidelines = len(records)
        total_sw_count = 0
        items = []

        for record, count in records:
            total_sw_count += count
            os_guide = OSGuideline.from_record(record)
            items.append(
                OSGuidelineCoverageItem(
                    guideline_id=os_guide.id,
                    os_name=os_guide.os_name,
                    status=os_guide.status.value,
                    coverage_count=count,
                )
            )

        average_coverage = (
            (total_sw_count / total_guidelines) if total_guidelines > 0 else 0.0
        )

        return OSGuidelineCoverageStats(
            total_os_guidelines=total_guidelines,
            average_coverage=round(average_coverage, 2),
            guidelines=items,
        )
