import os
import logging
import json
from typing import Optional, List
from .base import BlueprintService
from services import (
    MSFModuleService,
    VulnerabilityTargetService,
    OSGuidelineService,
    SoftwareGuidelineService,
)
from models import VulnerabilityTarget, GuidelineStatus
from agents import VMGuidelineGeneratorAgent


class MarkdownBlueprintService(BlueprintService):
    """
    Concrete implementation of BlueprintService that generates lab blueprint manuals in Markdown.
    """

    def __init__(
        self,
        msf_service: MSFModuleService,
        vuln_service: VulnerabilityTargetService,
        os_guide_service: OSGuidelineService,
        sw_guide_service: SoftwareGuidelineService,
        vm_guideline_generator_agent: VMGuidelineGeneratorAgent,
        output_dir: str = "vulnprint_blueprints/",
    ):
        self.msf_service = msf_service
        self.vuln_service = vuln_service
        self.output_dir = output_dir
        self.os_guide_service = os_guide_service
        self.sw_guide_service = sw_guide_service
        self.vm_guideline_generator_agent = vm_guideline_generator_agent
        self._logger = logging.getLogger(self.__class__.__name__)

    def generate_blueprint(self, msf_path: str) -> Optional[str]:
        """
        Reads database DTO records, maps them to domain models, and generates a beautiful,
        standardized Markdown blueprint manual.
        """
        try:
            # Query services for domain models
            msf_details = self.msf_service.get_module_details(msf_path)
            if not msf_details:
                self._logger.error(f"Module path '{msf_path}' not found.")
                return None

            vuln_target = self.vuln_service.get_vulnerability_target(msf_path)
            if not vuln_target:
                vuln_target = VulnerabilityTarget(software_name="Unknown")

            cves = msf_details.cves
            software_name = vuln_target.software_name
            vulnerable_versions = vuln_target.vulnerable_versions
            required_configs = vuln_target.required_configs
            os_guideline_text: Optional[str] = None
            software_guideline_text: Optional[str] = None
            os_name: str = "Unknown OS"

            # Retrieve Software guidelines from VM Guideline Service
            self._logger.info(f"Querying Software guideline for {msf_path}")
            sw_guidelines = self.sw_guide_service.get_software_guidelines_by_path(
                msf_path
            )
            if sw_guidelines:
                verified_guide = next(
                    (g for g in sw_guidelines if g.status == GuidelineStatus.VERIFIED),
                    None,
                )
                selected_sw_guide = (
                    verified_guide if verified_guide else sw_guidelines[0]
                )
                software_guideline_text = selected_sw_guide.guideline

                # Fetch corresponding OS Guideline
                os_guide = self.os_guide_service.get_os_guideline(
                    selected_sw_guide.os_guideline_id
                )
                if os_guide:
                    os_guideline_text = os_guide.guideline
                    os_name = os_guide.os_name
            else:
                self._logger.info(
                    f"Guideline for {msf_path} not directly found. Searching for suitable existing guideline..."
                )
                potential_guides = self.sw_guide_service.find_all_potential_guidelines(
                    platform=msf_details.platform,
                    software_name=software_name,
                    vulnerable_versions=vulnerable_versions,
                )
                if potential_guides:
                    self._logger.info(
                        f"Found {len(potential_guides)} suitable existing guideline(s) covering "
                        f"software '{software_name}'. Linking to {msf_path}."
                    )
                    # Link to all suitable guides
                    for _, guideline in potential_guides:
                        self.sw_guide_service.link_guideline_to_module(
                            msf_path, guideline.id
                        )
                    highest_score_guide = max(potential_guides, key=lambda x: x[0])[1]
                    software_guideline_text = highest_score_guide.guideline
                    os_guide = self.os_guide_service.get_os_guideline(
                        highest_score_guide.os_guideline_id
                    )
                    if os_guide:
                        os_guideline_text = os_guide.guideline
                        os_name = os_guide.os_name
                else:
                    self._logger.warning(
                        f"No suitable guideline found in database for {msf_path}. Regenerating using AI Agent..."
                    )
                    generated = self.vm_guideline_generator_agent.generate(msf_path)
                    if generated:
                        os_guide, sw_guide = generated
                        # 1. Store OS Guideline and get its ID
                        os_guideline_id = self.os_guide_service.store_os_guideline(
                            os_guide
                        )

                        # 2. Update software guideline fields and store it
                        sw_guide.os_guideline_id = os_guideline_id
                        sw_guide.software_id = (
                            vuln_target.id if vuln_target and vuln_target.id else 1
                        )

                        self.sw_guide_service.store_software_guideline(
                            sw_guide, msf_path
                        )
                        self._logger.info(
                            f"Stored the newly generated OS and Software guidelines for {msf_path}"
                        )
                        os_guideline_text = os_guide.guideline
                        os_name = os_guide.os_name
                        software_guideline_text = sw_guide.guideline
                    else:
                        self._logger.error(
                            f"Failed to generate guideline for {msf_path}. Using fallback instructions."
                        )

            # Build the exact template layout required
            template = self._build_markdown_template(
                msf_path=msf_path,
                cves=cves,
                vulnerable_versions=vulnerable_versions,
                required_configs=required_configs,
                os_name=os_name,
                os_guideline=os_guideline_text,
                software_guideline=software_guideline_text,
                software_name=software_name,
            )

            return self._export_blueprint_file(
                template=template, cves=cves, msf_path=msf_path
            )

        except Exception as e:
            self._logger.error(f"Error generating blueprint manual for {msf_path}: {e}")
            return None

    def _export_blueprint_file(self, template: str, cves: List[str], msf_path: str):
        # Create target directory if it does not exist
        os.makedirs(self.output_dir, exist_ok=True)

        # Determine appropriate filename
        if cves:
            # e.g., CVE-2020-1938.md
            filename = f"{cves[0].upper().strip()}.md"
        else:
            # Fallback to sanitized msf_path
            sanitized_path = msf_path.replace("/", "_").replace("\\", "_")
            filename = f"{sanitized_path}.md"

        full_filepath = os.path.join(self.output_dir, filename)

        # Write to file
        with open(full_filepath, "w", encoding="utf-8") as f:
            f.write(template)

        return full_filepath

    def _build_markdown_template(
        self,
        msf_path: str,
        cves: List[str],
        vulnerable_versions: List[str],
        required_configs: List[str],
        os_name: str,
        os_guideline: Optional[str],
        software_guideline: Optional[str],
        software_name: str,
    ):
        cves_str = ", ".join(cves) if cves else "N/A"
        versions_str = json.dumps(vulnerable_versions) if vulnerable_versions else "[]"
        configs_str = (
            "\n".join(f"{i}. {config}" for i, config in enumerate(required_configs, 1))
            if required_configs
            else "No special pre-requisite configurations identified."
        )

        if os_guideline and software_guideline:
            setup_block = (
                f"### 🖥️ Operating System Setup ({os_name})\n"
                f"{os_guideline}\n\n"
                f"### 💿 Software Installation ({software_name})\n"
                f"{software_guideline}"
            )
        else:
            setup_block = (
                "1. Download the specific legacy target executable or system binary package matching the versions identified above directly from standard open historical software archives.\n"
                "2. Initialize a local, network-isolated virtual machine or manual container image environment.\n"
                '3. Apply the environment parameters specified within the "Configuration Rules" section above.\n'
                "4. Verify local port binding allocations using standard troubleshooting utilities (`netstat`, `ss`, or `lsof`)."
            )

        template = (
            f"# 📄 Lab Blueprint Manual: {software_name}\n"
            f"## 🎯 Vulnerability Target Profile\n"
            f"- **Metasploit Core Path:** `{msf_path}`\n"
            f"- **Associated CVEs:** `{cves_str}`\n"
            f"- **Identified Vulnerable Product Versions:** `{versions_str}`\n"
            f"## ⚙️ Target System Pre-Requisites & Configuration Rules\n"
            f"{configs_str}\n"
            f"## 🛠️ Manual Lab Setup Instructions\n"
            f"{setup_block}\n"
        )
        return template
