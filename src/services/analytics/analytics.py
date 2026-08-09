import logging
import re
from typing import Optional
from .base import AnalyticsService
from services import (
    MSFModuleService,
    SoftwareService,
    SoftwareGuidelineService,
    OSGuidelineService,
    VMGuidelineService,
)
from utils import OutputBuffer, safe_print


class CLIAnalyticsService(AnalyticsService):
    """
    Concrete implementation of AnalyticsService displaying a clean ASCII metrics dashboard.
    Follows Approach 1: The Funnel Narrative Flow.
    """

    def __init__(
        self,
        msf_service: MSFModuleService,
        soft_service: SoftwareService,
        sw_guide_service: SoftwareGuidelineService,
        os_guide_service: OSGuidelineService,
        vm_guide_service: VMGuidelineService,
    ):
        self.msf_service = msf_service
        self.soft_service = soft_service
        self.sw_guide_service = sw_guide_service
        self.os_guide_service = os_guide_service
        self.vm_guide_service = vm_guide_service
        self._logger = logging.getLogger(self.__class__.__name__)

    def _clean_string(self, text: str) -> str:
        """Sanitizes text by stripping invalid/non-printable unicode characters."""
        if not text:
            return ""
        cleaned = text.replace("\ufffd", " ").replace("®", "").replace("™", "")
        return re.sub(r"\s+", " ", cleaned).strip()

    def _generate_bar(self, percentage: float, max_bar_length: int = 18) -> str:
        """Generates an ASCII progress bar for percentages."""
        if percentage < 0:
            percentage = 0.0
        elif percentage > 100:
            percentage = 100.0
        filled_length = int(round((percentage / 100) * max_bar_length))
        empty_length = max_bar_length - filled_length
        return "#" * filled_length + "." * empty_length

    def display_dashboard(self) -> None:
        """
        Outputs a 1-Page Executive Metrics Summary:
        Macro System KPIs -> Top Software Target Density -> Quick Minimal VM Recommendation.
        """
        try:
            print = safe_print
            total_count = self.msf_service.get_total_count()
            sw_stats = self.sw_guide_service.get_guideline_coverage_stats()
            os_stats = self.os_guide_service.get_os_guideline_coverage_stats()
            vm_coverage = self.vm_guide_service.get_minimal_vm_guidelines_coverage(
                total_count
            )

            total_sw_guides = sw_stats.total_guidelines
            total_os_guides = os_stats.total_os_guidelines
            minimal_vms = vm_coverage.minimal_os_guidelines_count

            print("\n" + "=" * 75)
            print(f"{'[ VULNPRINT EXECUTIVE METRICS SUMMARY ]':^75}")
            print("=" * 75)
            print(
                f"  Total Indexed Profiles : {total_count:<6} | Software Guidelines Mapped : {total_sw_guides}"
            )
            print(
                f"  OS Guidelines Active   : {total_os_guides:<6} | Minimal Lab VMs Required   : {minimal_vms}"
            )
            print("-" * 75)

            if total_count == 0:
                print(
                    "  No vulnerability profiles found in database. Ingest modules to populate dashboard."
                )
                print("=" * 75 + "\n")
                return

            # Section 1: Top Target Software Density
            print(f"\n{'[ TOP TARGET SOFTWARE DENSITY ]':^75}")
            print("-" * 75)
            print(
                f" {'Rank':<5}{'Guide ID':<10}{'Target Software Product':<28}{'Count':<7}{'Density Bar':<22}"
            )
            print("-" * 75)

            top_techs = self.soft_service.get_top_software(limit=10)
            sw_to_guide_ids = {}
            for item in sw_stats.guidelines:
                sw_to_guide_ids.setdefault(item.software_name, []).append(
                    item.guideline_id
                )

            for idx, (software_name, count) in enumerate(top_techs, 1):
                clean_name = self._clean_string(software_name)
                pct = (count / total_count) * 100
                guide_ids = sw_to_guide_ids.get(software_name, [])
                guide_str = ", ".join(str(g) for g in guide_ids) if guide_ids else "-"
                display_name = (
                    clean_name[:26] + ".." if len(clean_name) > 26 else clean_name
                )
                bar = self._generate_bar(pct, max_bar_length=12)
                print(
                    f"  {idx:<4}{guide_str:<10}{display_name:<28}{count:<7}{bar} ({pct:.1f}%)"
                )

            # Section 2: Quick Minimal VM Setup Recommendation Summary
            if vm_coverage.os_guidelines:
                print("\n" + "-" * 75)
                print(f"{'[ MINIMAL LAB VM RECOMMENDATION SUMMARY ]':^75}")
                print("-" * 75)
                print(
                    f" {'Rank':<5}{'OS Guide ID':<13}{'OS Environment Setup':<24}{'Covered':<10}{'Efficiency':<20}"
                )
                print("-" * 75)
                for idx, item in enumerate(vm_coverage.os_guidelines[:5], 1):
                    clean_os = self._clean_string(item.os_name)
                    display_os = (
                        clean_os[:22] + ".." if len(clean_os) > 22 else clean_os
                    )
                    pct = item.msf_modules_coverage_percentage
                    bar = self._generate_bar(pct, max_bar_length=10)
                    print(
                        f"  {idx:<4}{item.os_guideline_id:<13}{display_os:<24}{item.msf_modules_covered_count:<10}{bar} ({pct:.1f}%)"
                    )

            print("\n" + "=" * 75)
            print(
                "  HINT: Run 'python src/main.py analytics' for deep threat intelligence"
            )
            print("=" * 75 + "\n")

        except Exception as e:
            self._logger.error(f"Error displaying dashboard summary: {e}")

    def display_analytics(self, export_path: Optional[str] = None) -> None:
        """
        Displays a comprehensive 4-Phase Narrative Analytics Flow:
        Phase 1: Threat Landscape & Exploit Intelligence
        Phase 2: Target Software Breakdown & Density
        Phase 3: Actionable Lab Blueprints & Minimal VM Optimization
        """
        try:
            total_count = self.msf_service.get_total_count()
            buf = OutputBuffer(export_path)

            buf.write("=" * 75)
            buf.write(f"{'[ VULNPRINT DEEP-DIVE THREAT & LAB ANALYTICS ]':^75}")
            buf.write("=" * 75)
            buf.write(f" Total Indexed Vulnerability Profiles: {total_count}")
            buf.write("-" * 75)

            if total_count == 0:
                buf.write(
                    " No records found in database. Run search or ingestion first."
                )
                buf.write("=" * 75)
                buf.save()
                return

            # PHASE 1: THREAT LANDSCAPE & EXPLOIT INTELLIGENCE
            buf.write("\n" + "+" + "-" * 73 + "+")
            buf.write(f"| {'PHASE 1: THREAT LANDSCAPE & EXPLOIT PROFILE':<71} |")
            buf.write("+" + "-" * 73 + "+")

            # Panel 1.1: Exploit Reliability Distribution
            ranks = self.msf_service.get_rank_distribution()
            buf.write("\n [1.1] EXPLOIT RELIABILITY DISTRIBUTION")
            buf.write("-" * 75)
            buf.write(
                f" {'Reliability Rank':<18}{'Count':<8}{'Share':<10}{'Distribution Bar'}"
            )
            buf.write("-" * 75)
            for rank_name, count in ranks:
                pct = (count / total_count) * 100
                bar = self._generate_bar(pct, max_bar_length=18)
                buf.write(f"  {rank_name:<17}{count:<8}{pct:.1f}%     {bar}")

            # Panel 1.2: Target Platform Distribution
            platforms = self.msf_service.get_platform_distribution()
            platform_total = sum(c for _, c in platforms)
            buf.write("\n\n [1.2] TARGET PLATFORM BREAKDOWN")
            buf.write("-" * 75)
            buf.write(
                f" {'Target Platform':<18}{'Count':<8}{'Share':<10}{'Distribution Bar'}"
            )
            buf.write("-" * 75)
            for plat_name, count in platforms:
                pct = (count / platform_total * 100) if platform_total > 0 else 0
                bar = self._generate_bar(pct, max_bar_length=18)
                buf.write(f"  {plat_name:<17}{count:<8}{pct:.1f}%     {bar}")

            # Panel 1.3: Temporal Analysis (Disclosure Timeline)
            timeline = self.msf_service.get_disclosure_timeline()
            buf.write("\n\n [1.3] VULNERABILITY DISCLOSURE TIMELINE")
            buf.write("-" * 75)
            buf.write(
                f" {'Disclosure Year':<18}{'Count':<8}{'Share':<10}{'Distribution Bar'}"
            )
            buf.write("-" * 75)
            for year, count in timeline:
                pct = (count / total_count) * 100
                bar = self._generate_bar(pct, max_bar_length=18)
                buf.write(f"  {year:<17}{count:<8}{pct:.1f}%     {bar}")

            # PHASE 2: TARGET SOFTWARE BREAKDOWN & DENSITY
            buf.write("\n\n" + "+" + "-" * 73 + "+")
            buf.write(
                f"| {'PHASE 2: TARGET SOFTWARE DENSITY & GUIDELINE MAPPING':<71} |"
            )
            buf.write("+" + "-" * 73 + "+")

            sw_stats = self.sw_guide_service.get_guideline_coverage_stats()
            top_techs = self.soft_service.get_top_software(limit=15)
            sw_to_guide_ids = {}
            for item in sw_stats.guidelines:
                sw_to_guide_ids.setdefault(item.software_name, []).append(
                    item.guideline_id
                )

            buf.write(
                f" {'Rank':<5}{'Guide ID':<10}{'Software Target':<28}{'Count':<7}{'Density Bar'}"
            )
            buf.write("-" * 75)
            for idx, (software_name, count) in enumerate(top_techs, 1):
                clean_name = self._clean_string(software_name)
                pct = (count / total_count) * 100
                guide_ids = sw_to_guide_ids.get(software_name, [])
                guide_str = ", ".join(str(g) for g in guide_ids) if guide_ids else "-"
                display_name = (
                    clean_name[:26] + ".." if len(clean_name) > 26 else clean_name
                )
                bar = self._generate_bar(pct, max_bar_length=12)
                buf.write(
                    f"  {idx:<4}{guide_str:<10}{display_name:<28}{count:<7}{bar} ({pct:.1f}%)"
                )

            # PHASE 3: ACTIONABLE LAB BLUEPRINTS & MINIMAL VM OPTIMIZATION
            buf.write("\n\n" + "+" + "-" * 73 + "+")
            buf.write(
                f"| {'PHASE 3: ACTIONABLE LAB BLUEPRINT OPTIMIZATION (SET COVER)':<71} |"
            )
            buf.write("+" + "-" * 73 + "+")

            vm_coverage = self.vm_guide_service.get_minimal_vm_guidelines_coverage(
                total_count
            )
            buf.write(
                f" Total Metasploit Modules in DB      : {vm_coverage.total_msf_modules_in_db}"
            )
            buf.write(
                f" Total Coverable Modules (Guidelines): {vm_coverage.total_coverable_msf_modules}"
            )
            buf.write(
                f" Minimal VM Guidelines Needed        : {vm_coverage.minimal_os_guidelines_count}"
            )
            buf.write("-" * 75)

            if vm_coverage.minimal_os_guidelines_count > 0:
                buf.write(
                    f" {'Rank':<5}{'OS Guide ID':<13}{'OS Guideline Setup':<22}{'SW Count':<9}{'Modules':<9}{'Coverage Efficiency'}"
                )
                buf.write("-" * 75)
                for idx, item in enumerate(vm_coverage.os_guidelines, 1):
                    clean_os = self._clean_string(item.os_name)
                    display_os = (
                        clean_os[:20] + ".." if len(clean_os) > 20 else clean_os
                    )
                    pct = item.msf_modules_coverage_percentage
                    bar = self._generate_bar(pct, max_bar_length=10)
                    buf.write(
                        f"  {idx:<4}{item.os_guideline_id:<13}{display_os:<22}"
                        f"{item.software_guidelines_count:<9}{item.msf_modules_covered_count:<9}"
                        f"{bar} ({pct:.1f}%)"
                    )

            buf.write("\n" + "=" * 75)
            buf.write(" ACTIONABLE LAB DEPLOYMENT HINTS:")
            buf.write(
                "   - Use 'python src/main.py db search <software>' to inspect target details."
            )
            buf.write(
                "   - Use 'python src/main.py export os <guide_id>' to export VM setup blueprints."
            )
            buf.write("=" * 75)
            buf.save()
        except Exception as e:
            self._logger.error(f"Error displaying advanced analytics: {e}")

    def display_software_list(self, export_path: Optional[str] = None) -> None:
        """
        Displays a list of all unique software targets.
        """
        try:
            software_list = self.soft_service.get_all_software()
            buf = OutputBuffer(export_path)

            buf.write("=" * 75)
            buf.write(f"{'[ INDEXED SOFTWARE TARGETS ]':^75}")
            buf.write("=" * 75)

            if not software_list:
                buf.write(" No software profiles found in the database.")
                buf.write("=" * 75 + "\n")
                buf.save()
                return

            stats = self.sw_guide_service.get_guideline_coverage_stats()
            sw_to_guide_ids = {}
            for item in stats.guidelines:
                sw_to_guide_ids.setdefault(item.software_name, []).append(
                    item.guideline_id
                )

            for idx, name in enumerate(software_list, 1):
                clean_name = self._clean_string(name)
                guide_ids = sw_to_guide_ids.get(name, [])
                if guide_ids:
                    guide_str = ", ".join(str(gid) for gid in guide_ids)
                    buf.write(
                        f"  {idx:>3}. {clean_name} (Software Guide IDs: {guide_str})"
                    )
                else:
                    buf.write(f"  {idx:>3}. {clean_name}")

            buf.write("=" * 75)
            buf.save()
        except Exception as e:
            self._logger.error(f"Error displaying software list: {e}")

    def display_search_results(
        self,
        software_pattern: Optional[str] = None,
        platform: Optional[str] = None,
        rank: Optional[str] = None,
        min_date: Optional[str] = None,
        max_date: Optional[str] = None,
        msf_path: Optional[str] = None,
        no_guideline: bool = False,
        export_path: Optional[str] = None,
    ) -> None:
        """
        Displays wildcard search results with optional platform, rank, date, msf_path, and no_guideline filters.
        """
        try:
            search_results = self.msf_service.search_modules(
                software_pattern=software_pattern,
                platform=platform,
                rank=rank,
                min_date=min_date,
                max_date=max_date,
                msf_path=msf_path,
                no_guideline=no_guideline,
            )
            buf = OutputBuffer(export_path)

            buf.write("=" * 75)
            buf.write(f"{'[ LOCAL DATABASE SEARCH RESULTS ]':^75}")
            buf.write("=" * 75)

            filters = []
            if software_pattern:
                filters.append(f"Software: '{software_pattern}'")
            if platform:
                filters.append(f"Platform: '{platform}'")
            if rank:
                filters.append(f"Rank: '{rank}'")
            if min_date:
                filters.append(f"Min Date: '{min_date}'")
            if max_date:
                filters.append(f"Max Date: '{max_date}'")
            if msf_path:
                filters.append(f"MSF Path: '{msf_path}'")
            if no_guideline:
                filters.append("Missing Guideline: True")

            if filters:
                buf.write(f" Active Filters: {', '.join(filters)}")
                buf.write("-" * 75)

            buf.write(f" Total Matches Found: {len(search_results)}")
            buf.write("-" * 75)

            if not search_results:
                buf.write(" No matching records found.")
                buf.write("=" * 75)
                buf.save()
                return

            for msf_module, software in search_results:
                buf.write(f" [+] {msf_module.display_name}")
                buf.write(f"     Exploit Path: {msf_module.path}")
                buf.write(f"     Platform/OS:  {', '.join(msf_module.platforms)}")
                buf.write(f"     Exploit Rank: {msf_module.rank}")
                buf.write(f"     Disclosure Date: {msf_module.disclosure_date}")
                if software:
                    clean_sw = self._clean_string(software.name)
                    buf.write(f"     Target:       {clean_sw}")
                    buf.write(f"     CVEs:         {', '.join(software.cves)}")
                    buf.write(
                        f"     Versions:     {', '.join(software.vulnerable_versions)}"
                    )

                sw_guides = self.sw_guide_service.get_software_guidelines_by_path(
                    msf_module.path
                )
                if sw_guides:
                    sw_ids_str = ", ".join(str(g.id) for g in sw_guides)
                    buf.write(f"     Software Guide ID: {sw_ids_str}")
                    os_ids = sorted(
                        list(set(oid for g in sw_guides for oid in g.os_guideline_ids))
                    )
                    if os_ids:
                        os_ids_str = ", ".join(str(oid) for oid in os_ids)
                        buf.write(f"     OS Guide ID:       {os_ids_str}")
                buf.write("")

            buf.write("=" * 75)
            buf.save()
        except Exception as e:
            self._logger.error(f"Error displaying search results: {e}")
