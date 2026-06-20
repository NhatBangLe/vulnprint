import os
import logging
import json
from typing import Optional
from .base import BlueprintService
from services import MSFModuleService, VulnerabilityTargetService, VMGuidelineService
from models import VulnerabilityTarget, VMGuidelineStatus
from agents import VMGuidelineGeneratorAgent


class MarkdownBlueprintService(BlueprintService):
    """
    Concrete implementation of BlueprintService that generates lab blueprint manuals in Markdown.
    """

    def __init__(
        self,
        msf_service: MSFModuleService,
        vuln_service: VulnerabilityTargetService,
        guide_service: VMGuidelineService,
        vm_guideline_generator_agent: VMGuidelineGeneratorAgent,
        output_dir: str = "vulnprint_blueprints/",
    ):
        self.msf_service = msf_service
        self.vuln_service = vuln_service
        self.output_dir = output_dir
        self.guide_service = guide_service
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

            # Format strings for insertion into template
            cves_str = ", ".join(cves) if cves else "N/A"

            # Insert vulnerable versions as JSON array string or format nicely
            versions_str = (
                json.dumps(vulnerable_versions) if vulnerable_versions else "[]"
            )

            # Format pre-requisites configuration rules as a step-by-step numbered list
            if required_configs:
                configs_str = "\n".join(
                    f"{i}. {config}" for i, config in enumerate(required_configs, 1)
                )
            else:
                configs_str = "1. No special pre-requisite configurations identified."

            # Retrieve VM guideline from VM Guideline Service
            self._logger.info(f"Querying VM guideline for {msf_path}")
            vm_guidelines = self.guide_service.get_vm_guideline_by_path(msf_path)
            if vm_guidelines:
                verified_guide = next(
                    (
                        g
                        for g in vm_guidelines
                        if g.status == VMGuidelineStatus.VERIFIED
                    ),
                    None,
                )
                if verified_guide:
                    setup_instructions = verified_guide.guideline
                else:
                    setup_instructions = vm_guidelines[0].guideline
            else:
                self._logger.warning(
                    f"Guideline for {msf_path} not found in database or rejected. Regenerating..."
                )
                vm_guideline = self.vm_guideline_generator_agent.generate(msf_path)
                if vm_guideline:
                    self.guide_service.store_vm_guideline(vm_guideline)
                    self._logger.info(
                        f"Stored the newly generated VM guideline for {msf_path}"
                    )
                    setup_instructions = vm_guideline.guideline
                else:
                    self._logger.error(
                        f"Failed to generate guideline for {msf_path}. Using fallback instructions."
                    )
                    setup_instructions = (
                        "1. Download the specific legacy target executable or system binary package matching the versions identified above directly from standard open historical software archives.\n"
                        "2. Initialize a local, network-isolated virtual machine or manual container image environment.\n"
                        '3. Apply the environment parameters specified within the "Configuration Rules" section above.\n'
                        "4. Verify local port binding allocations using standard troubleshooting utilities (`netstat`, `ss`, or `lsof`)."
                    )

            # Build the exact template layout required
            template = f"""# 📄 Lab Blueprint Manual: {software_name}

## 🎯 Vulnerability Target Profile

- **Metasploit Core Path:** `{msf_path}`
- **Associated CVEs:** `{cves_str}`
- **Identified Vulnerable Product Versions:** `{versions_str}`

## ⚙️ Target System Pre-Requisites & Configuration Rules

{configs_str}

## 🛠️ Manual Lab Setup Instructions

{setup_instructions}
"""
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

        except Exception as e:
            self._logger.error(f"Error generating blueprint manual for {msf_path}: {e}")
            return None
