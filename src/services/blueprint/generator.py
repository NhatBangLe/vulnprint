from utils import handle_validation_error
from pydantic import ValidationError
import os
import logging
import json
from typing import Optional, List
from .base import BlueprintService
from services import (
    MSFModuleService,
    SoftwareService,
    OSGuidelineService,
    SoftwareGuidelineService,
)
from models import GuidelineStatus, Software
from agents import OSGuidelineGeneratorAgent, SoftwareGuidelineGeneratorAgent


class MarkdownBlueprintService(BlueprintService):
    """
    Concrete implementation of BlueprintService that generates lab blueprint manuals in Markdown.
    """

    def __init__(
        self,
        msf_service: MSFModuleService,
        soft_service: SoftwareService,
        os_guide_service: OSGuidelineService,
        sw_guide_service: SoftwareGuidelineService,
        os_guideline_generator_agent: OSGuidelineGeneratorAgent,
        software_guideline_generator_agent: SoftwareGuidelineGeneratorAgent,
        output_dir: str = "vulnprint_blueprints/",
    ):
        self.msf_service = msf_service
        self.soft_service = soft_service
        self.output_dir = output_dir
        self.os_guide_service = os_guide_service
        self.sw_guide_service = sw_guide_service
        self.os_guideline_generator_agent = os_guideline_generator_agent
        self.software_guideline_generator_agent = software_guideline_generator_agent
        self._logger = logging.getLogger(self.__class__.__name__)

    def generate_blueprint(self, msf_path: str) -> Optional[str]:
        try:
            msf_module = self.msf_service.get_module_by_path(msf_path)
            if not msf_module:
                self._logger.error(f"Module path '{msf_path}' not found.")
                return None

            software = self.soft_service.get_software_by_path(msf_path)
            if not software:
                software = Software(path=msf_path, name="Unknown")

            data = {
                "os_name": None,
                "os_guideline": None,
                "software_guideline": None,
            }

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
                data["software_guideline"] = selected_sw_guide.guideline

                # Fetch corresponding OS Guideline
                os_guide = self.os_guide_service.get_os_guideline_by_id(
                    selected_sw_guide.os_guideline_id
                )
                if os_guide:
                    data["os_guideline"] = os_guide.guideline
                    data["os_name"] = os_guide.os_name
            else:
                self._logger.info(
                    f"Guideline for {msf_path} not directly found. Searching for suitable existing OS guideline..."
                )
                potential_os_guides = (
                    self.os_guide_service.find_all_potential_guidelines(
                        target_system_id=software.target_system_id,
                        platforms=msf_module.platforms,
                    )
                )
                if potential_os_guides:
                    self._logger.info(
                        f"Found {len(potential_os_guides)} suitable existing OS guideline(s) matching requirements."
                    )
                    highest_score_os_guide = max(
                        potential_os_guides, key=lambda x: x[0]
                    )[1]
                    os_guideline_id = highest_score_os_guide.id
                    os_guide = highest_score_os_guide

                    self._logger.info(
                        f"Re-using OS guideline ID {os_guideline_id} ({os_guide.os_name}). Generating software guideline..."
                    )
                    sw_guide = self.software_guideline_generator_agent.generate(
                        msf_path, os_guideline_id
                    )
                    if sw_guide:
                        sw_guide.os_guideline_id = os_guideline_id
                        sw_guide.software_id = (
                            software.id if software and software.id else 1
                        )
                        sw_guide_id = self.sw_guide_service.store_software_guideline(
                            sw_guide
                        )
                        if sw_guide_id is None:
                            raise Exception(
                                f"Failed to store software guideline for {msf_path}"
                            )
                        self._logger.info(
                            f"Stored software guideline with ID {sw_guide_id} for {msf_path}"
                        )
                        data["os_guideline"] = os_guide.guideline
                        data["os_name"] = os_guide.os_name
                        data["software_guideline"] = sw_guide.guideline
                    else:
                        self._logger.error(
                            f"Failed to generate software guideline for {msf_path} using reused OS guideline ID {os_guideline_id}."
                        )
                else:
                    self._logger.warning(
                        f"No suitable OS guideline found in database for {msf_path}. Regenerating OS guideline using AI Agent..."
                    )
                    os_guide = self.os_guideline_generator_agent.generate(msf_path)
                    if os_guide:
                        # 1. Store OS Guideline and get its ID
                        os_guideline_id = self.os_guide_service.store_os_guideline(
                            os_guide
                        )
                        if os_guideline_id is None:
                            raise Exception(
                                f"Failed to store OS guideline for {msf_path}"
                            )

                        # 2. Generate software guideline using the new OS guideline ID
                        sw_guide = self.software_guideline_generator_agent.generate(
                            msf_path, os_guideline_id
                        )
                        if sw_guide:
                            sw_guide.os_guideline_id = os_guideline_id
                            sw_guide.software_id = (
                                software.id if software and software.id else 1
                            )
                            sw_guide_id = (
                                self.sw_guide_service.store_software_guideline(sw_guide)
                            )
                            if sw_guide_id is None:
                                raise Exception(
                                    f"Failed to store software guideline for {msf_path}"
                                )

                            self._logger.info(
                                f"Stored the newly generated OS and Software guidelines for {msf_path}"
                            )
                            data["os_guideline"] = os_guide.guideline
                            data["os_name"] = os_guide.os_name
                            data["software_guideline"] = sw_guide.guideline
                        else:
                            self._logger.error(
                                f"Failed to generate software guideline for {msf_path}."
                            )
                    else:
                        self._logger.error(
                            f"Failed to generate OS guideline for {msf_path}. Using fallback instructions."
                        )

            # Build the exact template layout required
            template = self._build_markdown_template(
                msf_path=msf_path,
                cves=software.cves,
                vulnerable_versions=software.vulnerable_versions,
                required_configs=software.required_configs,
                os_name=data["os_name"],
                os_guideline=data["os_guideline"],
                software_guideline=data["software_guideline"],
                software_name=software.name,
            )

            return self._export_blueprint_file(
                template=template, cves=software.cves, msf_path=msf_path
            )
        except ValidationError as e:
            handle_validation_error(e, self._logger)
            return None
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
        os_name: Optional[str],
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
