import os
import logging
import json
from typing import Optional

try:
    from src.blueprint.base import BlueprintService
    from src.database import VulnerabilityRepository
except ImportError:
    from .base import BlueprintService
    from database import VulnerabilityRepository


class MarkdownBlueprintService(BlueprintService):
    """
    Concrete implementation of BlueprintService that generates lab blueprint manuals in Markdown.
    """

    def __init__(
        self,
        repository: VulnerabilityRepository,
        output_dir: str = "vulnprint_blueprints/",
    ):
        self.repository = repository
        self.output_dir = output_dir
        self._logger = logging.getLogger(self.__class__.__name__)

    def generate_blueprint(self, msf_path: str) -> Optional[str]:
        """
        Reads a database entry from the VulnerabilityRepository and generates a beautiful,
        standardized Markdown blueprint manual.
        """
        try:
            # Query the repository
            vuln = self.repository.get_vulnerability(msf_path)
            if not vuln:
                self._logger.error(
                    f"Module path '{msf_path}' not found in database repository."
                )
                return None

            cves = vuln.cves
            software_name = vuln.software_name
            vulnerable_versions = vuln.vulnerable_versions
            required_configs = vuln.required_configs

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

            # Build the exact template layout required
            template = f"""# 📄 Lab Blueprint Manual: {software_name}

## 🎯 Vulnerability Target Profile

- **Metasploit Core Path:** `{msf_path}`
- **Associated CVEs:** `{cves_str}`
- **Identified Vulnerable Product Versions:** `{versions_str}`

## ⚙️ Target System Pre-Requisites & Configuration Rules

{configs_str}

## 🛠️ Manual Lab Setup Instructions

1. Download the specific legacy target executable or system binary package matching the versions identified above directly from standard open historical software archives.
2. Initialize a local, network-isolated virtual machine or manual container image environment.
3. Apply the environment parameters specified within the "Configuration Rules" section above.
4. Verify local port binding allocations using standard troubleshooting utilities (`netstat`, `ss`, or `lsof`).

## ⚔️ Verification & Exploitation Testing Lifecycle

Launch `msfconsole`, initialize communications, and utilize these precise directives to execute validation scripts against your manual host target environment:

```msf
use {msf_path}
set RHOSTS <TARGET_VIRTUAL_MACHINE_IP>
set RPORT <TARGET_SERVICE_PORT>
check
run
```
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
