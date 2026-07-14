from models import OSGuideline
import logging
from typing import Set, List, Any, Dict, Optional
from models import (
    GuidelineStatus,
    MinimalVMGuidelineItem,
    MinimalVMGuidelinesCoverage,
)
from services import OSGuidelineService, SoftwareGuidelineService
from .base import VMGuidelineService


class DefaultVMGuidelineService(VMGuidelineService):
    """
    Default implementation of VMGuidelineService using a Greedy Set Cover algorithm.
    """

    def __init__(
        self,
        os_guide_service: OSGuidelineService,
        sw_guide_service: SoftwareGuidelineService,
    ):
        self.os_guide_service = os_guide_service
        self.sw_guide_service = sw_guide_service
        self._logger = logging.getLogger(self.__class__.__name__)

    def get_minimal_vm_guidelines_coverage(
        self, total_msf_modules: int
    ) -> MinimalVMGuidelinesCoverage:
        try:
            # 1. Fetch all OS guidelines and filter out rejected ones
            all_os_guidelines = self.os_guide_service.get_all_guidelines()
            candidate_os_guidelines = [
                og for og in all_os_guidelines if og.status != GuidelineStatus.REJECTED
            ]

            # 2. Map candidate OS guidelines to their linked software guidelines and covered modules
            candidates_data: Dict[int, Dict[str, Any]] = {}
            universe: Set[str] = set()

            for og in candidate_os_guidelines:
                if og.id is None:
                    continue

                sw_guidelines = self.sw_guide_service.get_software_guidelines_by_os_id(
                    og.id
                )
                # Filter out standard candidates with no linked software guidelines
                if not sw_guidelines:
                    continue

                # Gather unique software setup IDs and covered MSF module paths
                software_ids = set()
                module_paths = set()
                for sw_g in sw_guidelines:
                    software_ids.add(sw_g.software_id)
                    if sw_g.path:
                        module_paths.add(sw_g.path)

                candidates_data[og.id] = {
                    "os_guideline": og,
                    "software_count": len(software_ids),
                    "modules": module_paths,
                }
                universe.update(module_paths)

            # 3. Greedy Set Cover Algorithm
            uncovered = set(universe)
            selected_ids: List[int] = []

            while uncovered:
                best_os_id: Optional[int] = None
                best_covered_now: Set[str] = set()

                for os_id, data in candidates_data.items():
                    if os_id in selected_ids:
                        continue

                    modules: Set[str] = data["modules"]
                    covered_now = modules & uncovered
                    if len(covered_now) > len(best_covered_now):
                        best_os_id = os_id
                        best_covered_now = covered_now
                    elif (
                        len(covered_now) == len(best_covered_now)
                        and len(best_covered_now) > 0
                    ):
                        # Tie-breaker: prefer smaller OS guideline ID
                        if best_os_id is None or os_id < best_os_id:
                            best_os_id = os_id
                            best_covered_now = covered_now

                if not best_os_id or len(best_covered_now) == 0:
                    break

                selected_ids.append(best_os_id)
                uncovered -= best_covered_now

            # 4. Construct response items
            selected_items: List[MinimalVMGuidelineItem] = []
            for os_id in selected_ids:
                data = candidates_data[os_id]
                og: OSGuideline = data["os_guideline"]
                modules_list: List[str] = sorted(list(data["modules"]))
                modules_count: int = len(modules_list)

                coverage_pct = (
                    ((modules_count / total_msf_modules) * 100.0)
                    if total_msf_modules > 0
                    else 0.0
                )

                selected_items.append(
                    MinimalVMGuidelineItem(
                        os_guideline_id=os_id,
                        os_name=og.os_name,
                        os_guideline_status=og.status.value,
                        software_guidelines_count=data["software_count"],
                        msf_modules_covered_count=modules_count,
                        msf_modules_coverage_percentage=round(coverage_pct, 2),
                        msf_modules_covered=modules_list,
                    )
                )

            # 5. Sort final items by coverage percentage descending, then by ID ascending
            selected_items.sort(
                key=lambda x: (-x.msf_modules_coverage_percentage, x.os_guideline_id)
            )

            return MinimalVMGuidelinesCoverage(
                total_msf_modules_in_db=total_msf_modules,
                total_coverable_msf_modules=len(universe),
                minimal_os_guidelines_count=len(selected_items),
                os_guidelines=selected_items,
            )

        except Exception as e:
            self._logger.error(f"Error calculating minimal VM guidelines coverage: {e}")
            return MinimalVMGuidelinesCoverage(
                total_msf_modules_in_db=total_msf_modules,
                total_coverable_msf_modules=0,
                minimal_os_guidelines_count=0,
                os_guidelines=[],
            )
