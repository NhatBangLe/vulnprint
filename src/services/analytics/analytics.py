import logging
from typing import Optional
from .base import AnalyticsService
from services import (
    MSFModuleService,
    VulnerabilityTargetService,
    SoftwareGuidelineService,
)
from models import VulnerabilityTarget
from utils import OutputBuffer


class CLIAnalyticsService(AnalyticsService):
    """
    Concrete implementation of AnalyticsService displaying an ASCII dashboard in the terminal.
    """

    def __init__(
        self,
        msf_service: MSFModuleService,
        vuln_service: VulnerabilityTargetService,
        sw_guide_service: SoftwareGuidelineService,
    ):
        self.msf_service = msf_service
        self.vuln_service = vuln_service
        self.sw_guide_service = sw_guide_service
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

            # Query Top 10 technologies from VulnerabilityTargetService
            top_techs = self.vuln_service.get_top_technologies(limit=10)

            # Header for the table
            print(f"{'Rank':<6}{'Software Target':<36}{'Count':<10}{'Percentage':<10}")
            print("-" * 70)

            for idx, (software_name, count) in enumerate(top_techs, 1):
                percentage = (count / total_count) * 100
                percentage_str = f"{percentage:.1f}%"
                display_name = (
                    software_name[:34] + ".."
                    if len(software_name) > 34
                    else software_name
                )
                print(f"{idx:<6}{display_name:<36}{count:<10}{percentage_str:<10}")

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
            configs = self.vuln_service.get_required_configurations()
            if configs:
                from collections import Counter

                config_counts = Counter(configs).most_common(5)
                buf.write("\n" + "=" * 70)
                buf.write(f"{'COMMON LAB CONFIGURATION FLAGS':^70}")
                buf.write("=" * 70)
                buf.write(f" {'Configuration Requirement':<55}{'Occurrences':<10}")
                buf.write("-" * 70)
                for idx, (config_name, count) in enumerate(config_counts, 1):
                    display_config = (
                        config_name[:52] + ".."
                        if len(config_name) > 52
                        else config_name
                    )
                    buf.write(f" {idx}. {display_config:<51}{count:<10}")
                buf.write("=" * 70)

            # Panel 5: VM Guideline Coverage & Consolidation
            stats = self.sw_guide_service.get_guideline_coverage_stats()
            buf.write("\n" + "=" * 70)
            buf.write(f"{'VM GUIDELINE COVERAGE & CONSOLIDATION':^70}")
            buf.write("=" * 70)
            buf.write(f" Total Unique VM Guidelines: {stats.total_guidelines}")
            buf.write(f" Average Module Coverage per VM: {stats.average_coverage:.2f}")
            buf.write("-" * 70)
            if stats.total_guidelines > 0:
                buf.write(
                    f" {'VM ID':<8}{'Target Software Product':<36}{'Status':<14}{'MSF Covered'}"
                )
                buf.write("-" * 70)
                for item in stats.guidelines:
                    display_software = (
                        item.software_name[:34] + ".."
                        if len(item.software_name) > 34
                        else item.software_name
                    )
                    buf.write(
                        f" {item.guideline_id:<8}"
                        f"{display_software:<36}"
                        f"{item.status:<14}"
                        f"{item.coverage_count}"
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
            software_list = self.vuln_service.get_all_software()
            buf = OutputBuffer(export_path)

            buf.write("=" * 70)
            buf.write(f"{'INDEXED SOFTWARE TARGETS':^70}")
            buf.write("=" * 70)

            if not software_list:
                buf.write(" No software profiles found in the database.")
                buf.write("=" * 70 + "\n")
                buf.save()
                return

            for idx, name in enumerate(software_list, 1):
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
            # Query joined records from MSFModuleService
            msf_modules = self.msf_service.search_modules(
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

            buf.write(f" Total Matches Found: {len(msf_modules)}")
            buf.write("-" * 70)

            if not msf_modules:
                buf.write(" No matching records found.")
                buf.write("=" * 70)
                buf.save()
                return

            current_software = None
            for msf_details in msf_modules:
                path = msf_details.module_name
                vuln_target = self.vuln_service.get_vulnerability_target(path)
                if not vuln_target:
                    vuln_target = VulnerabilityTarget(software_name="Unknown")

                if vuln_target.software_name != current_software:
                    current_software = vuln_target.software_name
                    buf.write(f"\n[Software Target: {current_software}]")
                    buf.write("-" * 70)

                buf.write(f" [+] {msf_details.name}")
                buf.write(f"     Exploit Path: {path}")
                if msf_details.cves:
                    buf.write(f"     CVEs:         {', '.join(msf_details.cves)}")
                if msf_details.platform:
                    buf.write(f"     Platform/OS:  {', '.join(msf_details.platform)}")
                if msf_details.rank:
                    buf.write(f"     Exploit Rank: {msf_details.rank}")
                if vuln_target.vulnerable_versions:
                    buf.write(
                        f"     Versions:     {', '.join(vuln_target.vulnerable_versions)}"
                    )
                buf.write("")

            buf.write("=" * 70)
            buf.save()
        except Exception as e:
            self._logger.error(f"Error displaying search results: {e}")
