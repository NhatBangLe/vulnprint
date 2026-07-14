import logging
from typing import Optional
from .base import AnalyticsService
from services import (
    MSFModuleService,
    SoftwareService,
    SoftwareGuidelineService,
    OSGuidelineService,
)
from utils import OutputBuffer, safe_print


class CLIAnalyticsService(AnalyticsService):
    """
    Concrete implementation of AnalyticsService displaying an ASCII dashboard in the terminal.
    """

    def __init__(
        self,
        msf_service: MSFModuleService,
        soft_service: SoftwareService,
        sw_guide_service: SoftwareGuidelineService,
        os_guide_service: OSGuidelineService,
    ):
        self.msf_service = msf_service
        self.soft_service = soft_service
        self.sw_guide_service = sw_guide_service
        self.os_guide_service = os_guide_service
        self._logger = logging.getLogger(self.__class__.__name__)

    def _generate_bar(self, percentage: float, max_bar_length: int = 25) -> str:
        """Generates an ASCII bar representing the percentage."""
        filled_length = int(round((percentage / 100) * max_bar_length))
        return "█" * filled_length

    def display_dashboard(self) -> None:
        """
        Outputs a beautiful CLI ASCII dashboard of the Top 10 software targets.
        """
        try:
            print = safe_print
            total_count = self.msf_service.get_total_count()

            print("\n" + "=" * 70)
            print(f"{'VULNPRINT TECHNOLOGY DENSITY METRICS':^70}")
            print("=" * 70)
            print(f" Total Vulnerability Profiles Indexed: {total_count}")
            print("-" * 70)

            if total_count == 0:
                print(" No records found in the database. Run a search first.")
                print("=" * 70 + "\n")
                return

            # Query Top 10 technologies from SoftwareService
            top_techs = self.soft_service.get_top_software(limit=10)

            # Get software guidelines mapping to software names to display their Guide IDs
            stats = self.sw_guide_service.get_guideline_coverage_stats()
            sw_to_guide_ids = {}
            for item in stats.guidelines:
                sw_to_guide_ids.setdefault(item.software_name, []).append(
                    item.guideline_id
                )

            # Header for the table
            print(
                f"{'Rank':<6}{'Guide IDs':<12}{'Software Target':<30}{'Count':<8}{'Percentage':<10}"
            )
            print("-" * 70)

            for idx, (software_name, count) in enumerate(top_techs, 1):
                percentage = (count / total_count) * 100
                percentage_str = f"{percentage:.1f}%"
                guide_ids = sw_to_guide_ids.get(software_name, [])
                guide_str = (
                    ", ".join(str(gid) for gid in guide_ids) if guide_ids else "-"
                )
                display_name = (
                    software_name[:28] + ".."
                    if len(software_name) > 28
                    else software_name
                )
                print(
                    f"{idx:<6}{guide_str:<12}{display_name:<30}{count:<8}{percentage_str:<10}"
                )

            print("=" * 70 + "\n")

            # Query OS guideline coverage summary
            os_stats = self.os_guide_service.get_os_guideline_coverage_stats()
            total_os_sw_guides = sum(
                item.coverage_count for item in os_stats.guidelines
            )

            print("=" * 70)
            print(f"{'OS GUIDELINE COVERAGE SUMMARY':^70}")
            print("=" * 70)
            print(f" Total Software Guidelines Covered: {total_os_sw_guides}")
            print("-" * 70)

            if total_os_sw_guides == 0:
                print(
                    " No software guidelines linked to OS guidelines found in the database."
                )
                print("=" * 70 + "\n")
            else:
                print(
                    f"{'Rank':<6}{'Guide ID':<10}{'OS Guideline Setup':<30}{'SW Covered':<12}{'Percentage':<10}"
                )
                print("-" * 70)
                for idx, item in enumerate(os_stats.guidelines, 1):
                    percentage = (
                        (item.coverage_count / total_os_sw_guides) * 100
                        if total_os_sw_guides > 0
                        else 0
                    )
                    percentage_str = f"{percentage:.1f}%"
                    display_name = (
                        item.os_name[:28] + ".."
                        if len(item.os_name) > 28
                        else item.os_name
                    )
                    print(
                        f"{idx:<6}{item.guideline_id:<10}{display_name:<30}{item.coverage_count:<12}{percentage_str:<10}"
                    )
                print("=" * 70 + "\n")

        except Exception as e:
            self._logger.error(f"Error displaying analytics: {e}")

    def display_analytics(self, export_path: Optional[str] = None) -> None:
        """
        Displays detailed statistical metrics dashboard panels.
        """
        try:
            total_count = self.msf_service.get_total_count()
            buf = OutputBuffer(export_path)

            buf.write("=" * 70)
            buf.write(f"{'VULNPRINT INTELLIGENCE DETAILED ANALYTICS':^70}")
            buf.write("=" * 70)
            buf.write(f" Total Indexed Vulnerability Profiles: {total_count}")
            buf.write("-" * 70)

            if total_count == 0:
                buf.write(" No records found in the database. Run a search first.")
                buf.write("=" * 70)
                buf.save()
                return

            # Panel 1: Exploit Reliability Distribution
            ranks = self.msf_service.get_rank_distribution()
            buf.write("\n" + "=" * 70)
            buf.write(f"{'EXPLOIT RELIABILITY DISTRIBUTION':^70}")
            buf.write("=" * 70)
            buf.write(f" {'Rank':<12}{'Count':<10}{'Percentage':<12}{'Bar Chart'}")
            buf.write("-" * 70)
            for rank_name, count in ranks:
                pct = (count / total_count) * 100
                pct_str = f"{pct:.1f}%"
                bar = self._generate_bar(pct)
                buf.write(f" {rank_name:<12}{count:<10}{pct_str:<12}{bar}")
            buf.write("=" * 70)

            # Panel 2: Target Platform & OS Coverage
            platforms = self.msf_service.get_platform_distribution()
            platform_total = sum(count for _, count in platforms)
            buf.write("\n" + "=" * 70)
            buf.write(f"{'TARGET PLATFORM DISTRIBUTION':^70}")
            buf.write("=" * 70)
            buf.write(f" {'Platform':<12}{'Count':<10}{'Percentage':<12}{'Bar Chart'}")
            buf.write("-" * 70)
            for plat_name, count in platforms:
                pct = (count / platform_total * 100) if platform_total > 0 else 0
                pct_str = f"{pct:.1f}%"
                bar = self._generate_bar(pct)
                buf.write(f" {plat_name:<12}{count:<10}{pct_str:<12}{bar}")
            buf.write("=" * 70)

            # Panel 3: Temporal Analysis (Disclosure Timeline)
            timeline = self.msf_service.get_disclosure_timeline()
            buf.write("\n" + "=" * 70)
            buf.write(f"{'VULNERABILITY DISCLOSURE TIMELINE':^70}")
            buf.write("=" * 70)
            buf.write(f" {'Year':<12}{'Count':<10}{'Percentage':<12}{'Bar Chart'}")
            buf.write("-" * 70)
            for year, count in timeline:
                pct = (count / total_count) * 100
                pct_str = f"{pct:.1f}%"
                bar = self._generate_bar(pct)
                buf.write(f" {year:<12}{count:<10}{pct_str:<12}{bar}")
            buf.write("=" * 70)

            # Panel 4: Common Required Configurations
            # configs = self.soft_service.get_required_configurations()
            # if configs:
            #     from collections import Counter

            #     config_counts = Counter(configs).most_common(5)
            #     buf.write("\n" + "=" * 70)
            #     buf.write(f"{'COMMON LAB CONFIGURATION FLAGS':^70}")
            #     buf.write("=" * 70)
            #     buf.write(f" {'Configuration Requirement':<55}{'Occurrences':<10}")
            #     buf.write("-" * 70)
            #     for idx, (config_name, count) in enumerate(config_counts, 1):
            #         display_config = (
            #             config_name[:52] + ".."
            #             if len(config_name) > 52
            #             else config_name
            #         )
            #         buf.write(f" {idx}. {display_config:<51}{count:<10}")
            #     buf.write("=" * 70)

            # Panel 5: Software Guideline Coverage & Consolidation
            stats = self.sw_guide_service.get_guideline_coverage_stats()
            buf.write("\n" + "=" * 70)
            buf.write(f"{'SOFTWARE GUIDELINE COVERAGE & CONSOLIDATION':^70}")
            buf.write("=" * 70)
            buf.write(f" Total Unique Software Guidelines: {stats.total_guidelines}")
            buf.write(
                f" Average Module Coverage per Software Guideline: {stats.average_coverage:.2f}"
            )
            buf.write("-" * 70)
            if stats.total_guidelines > 0:
                buf.write(
                    f" {'Guide ID':<10}{'Target Software Product':<36}{'Status':<14}{'MSF Covered'}"
                )
                buf.write("-" * 70)
                for item in stats.guidelines:
                    display_software = (
                        item.software_name[:34] + ".."
                        if len(item.software_name) > 34
                        else item.software_name
                    )
                    buf.write(
                        f" {item.guideline_id:<10}"
                        f"{display_software:<36}"
                        f"{item.status:<14}"
                        f"{item.coverage_count}"
                    )
                buf.write("=" * 70)

            # Panel 6: OS Guideline Coverage Distribution
            os_stats = self.os_guide_service.get_os_guideline_coverage_stats()
            total_os_sw_guides = sum(
                item.coverage_count for item in os_stats.guidelines
            )
            buf.write("\n" + "=" * 70)
            buf.write(f"{'OS GUIDELINE COVERAGE DISTRIBUTION':^70}")
            buf.write("=" * 70)
            buf.write(f" Total Unique OS Guidelines: {os_stats.total_os_guidelines}")
            buf.write(
                f" Average Software Coverage per OS Guideline: {os_stats.average_coverage:.2f}"
            )
            buf.write("-" * 70)
            if os_stats.total_os_guidelines > 0:
                buf.write(
                    f" {'Rank':<6}{'Guide ID':<10}{'OS Guideline Setup':<20}{'SW Covered':<12}{'Percentage':<12}{'Bar Chart'}"
                )
                buf.write("-" * 70)
                for idx, item in enumerate(os_stats.guidelines, 1):
                    pct = (
                        (item.coverage_count / total_os_sw_guides * 100)
                        if total_os_sw_guides > 0
                        else 0
                    )
                    pct_str = f"{pct:.1f}%"
                    bar = self._generate_bar(pct)
                    display_name = (
                        item.os_name[:18] + ".."
                        if len(item.os_name) > 18
                        else item.os_name
                    )
                    buf.write(
                        f" {idx:<5}{item.guideline_id:<10}{display_name:<20}{item.coverage_count:<12}{pct_str:<12}{bar}"
                    )
                buf.write("=" * 70)

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

            buf.write("=" * 70)
            buf.write(f"{'INDEXED SOFTWARE TARGETS':^70}")
            buf.write("=" * 70)

            if not software_list:
                buf.write(" No software profiles found in the database.")
                buf.write("=" * 70 + "\n")
                buf.save()
                return

            # Get guideline coverage stats to map software names to guideline IDs
            stats = self.sw_guide_service.get_guideline_coverage_stats()
            sw_to_guide_ids = {}
            for item in stats.guidelines:
                sw_to_guide_ids.setdefault(item.software_name, []).append(
                    item.guideline_id
                )

            for idx, name in enumerate(software_list, 1):
                guide_ids = sw_to_guide_ids.get(name, [])
                if guide_ids:
                    guide_str = ", ".join(str(gid) for gid in guide_ids)
                    buf.write(f"  {idx:>3}. {name} (Software Guide IDs: {guide_str})")
                else:
                    buf.write(f"  {idx:>3}. {name}")

            buf.write("=" * 70)
            buf.save()
        except Exception as e:
            self._logger.error(f"Error displaying software list: {e}")

    def display_search_results(
        self,
        software_pattern: str,
        platform: Optional[str] = None,
        rank: Optional[str] = None,
        export_path: Optional[str] = None,
    ) -> None:
        """
        Displays wildcard search results with optional platform and rank filters.
        """
        try:
            search_results = self.msf_service.search_modules(
                software_pattern=software_pattern, platform=platform, rank=rank
            )
            buf = OutputBuffer(export_path)

            buf.write("=" * 70)
            buf.write(f"{'LOCAL DATABASE SEARCH RESULTS':^70}")
            buf.write("=" * 70)

            filters = []
            if software_pattern:
                filters.append(f"Software: '{software_pattern}'")
            if platform:
                filters.append(f"Platform: '{platform}'")
            if rank:
                filters.append(f"Rank: '{rank}'")

            if filters:
                buf.write(f" Active Filters: {', '.join(filters)}")
                buf.write("-" * 70)

            buf.write(f" Total Matches Found: {len(search_results)}")
            buf.write("-" * 70)

            if not search_results:
                buf.write(" No matching records found.")
                buf.write("=" * 70)
                buf.save()
                return

            for msf_module, software in search_results:
                buf.write(f" [+] {msf_module.display_name}")
                buf.write(f"     Exploit Path: {msf_module.path}")
                buf.write(f"     Platform/OS:  {', '.join(msf_module.platforms)}")
                buf.write(f"     Exploit Rank: {msf_module.rank}")
                buf.write(f"     Disclosure Date: {msf_module.disclosure_date}")
                if software:
                    buf.write(f"     Target:       {software.name}")
                    buf.write(f"     CVEs:         {', '.join(software.cves)}")
                    buf.write(
                        f"     Versions:     {', '.join(software.vulnerable_versions)}"
                    )

                # Retrieve and display associated guideline IDs for tracking/exporting
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

            buf.write("=" * 70)
            buf.save()
        except Exception as e:
            self._logger.error(f"Error displaying search results: {e}")
