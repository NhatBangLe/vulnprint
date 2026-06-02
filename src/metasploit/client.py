import re
import time
import logging
from pymetasploit3.msfrpc import MsfRpcClient
from typing import List

try:
    from src.metasploit.base import MetasploitService
    from src.models import MetasploitModuleDetails
except ImportError:
    from .base import MetasploitService
    from models import MetasploitModuleDetails


class MetasploitRPCService(MetasploitService):
    """
    Concrete implementation of MetasploitService communicating over MSF RPC.
    """

    def __init__(self, host: str, port: int, password: str):
        self.host = host
        self.port = port
        self.password = password
        self.client = None
        self._logger = logging.getLogger(self.__class__.__name__)

    def connect(self) -> None:
        """
        Initializes and returns an authenticated MsfRpcClient connection.
        """
        try:
            self.client = MsfRpcClient(
                password=self.password, port=self.port, server=self.host
            )
        except Exception as e:
            self._logger.error(
                f"Failed to connect to Metasploit RPC server at {self.host}:{self.port} - {e}"
            )
            raise

    def search_modules(self, search_string: str) -> List[str]:
        """
        Queries Metasploit's console for exploits matching the search_string
        and parses out the module paths.
        """
        if not self.client:
            raise RuntimeError("Client is not connected. Call connect() first.")

        console_id = None
        try:
            # Spawn an active virtual console session
            console_data = self.client.consoles.console.create()
            console_id = console_data.get("id")
            if console_id is None:
                raise RuntimeError(
                    "Failed to obtain a valid console ID from Metasploit RPC server."
                )

            console = self.client.consoles.console(console_id)

            # Send precise CLI search directive
            command = f"search {search_string}\n"
            console.write(command)

            # Pause explicitly for the buffer to fill
            time.sleep(2)

            # Read the raw console output string
            output_data = console.read()
            raw_output = (
                output_data.get("data", "")
                if isinstance(output_data, dict)
                else str(output_data)
            )

            # Parse module paths using regex
            module_paths = re.findall(r"(exploit/[\w/_-]+)", raw_output)

            # Ensure unique paths sorted alphabetically
            return sorted(list(set(module_paths)))

        except Exception as e:
            self._logger.error(f"Error executing Metasploit query: {e}")
            return []
        finally:
            # Destroy console session to avoid session leaks
            if console_id is not None:
                try:
                    self.client.consoles.console(console_id).destroy()
                except Exception as destroy_error:
                    self._logger.warning(
                        f"Failed to destroy console session {console_id}: {destroy_error}"
                    )

    def get_module_details(self, module_path: str) -> MetasploitModuleDetails:
        """
        Retrieves the description and CVE references for a specific module path.
        Discards all other meta-information to conserve token window budget.
        """
        if not self.client:
            raise RuntimeError("Client is not connected. Call connect() first.")

        try:
            # Load the module
            exploit = self.client.modules.use("exploit", module_path)

            # Extract raw description
            description = getattr(exploit, "description", "")
            if isinstance(description, bytes):
                description = description.decode("utf-8", errors="ignore")

            # Isolate CVE reference codes
            raw_references = getattr(exploit, "references", [])
            cves = []

            for ref in raw_references:
                if isinstance(ref, (list, tuple)) and len(ref) >= 2:
                    ref_type = str(ref[0]).upper().strip()
                    ref_val = str(ref[1]).strip()

                    if ref_type == "CVE":
                        if not ref_val.upper().startswith("CVE-"):
                            cves.append(f"CVE-{ref_val}")
                        else:
                            cves.append(ref_val)

            return MetasploitModuleDetails(
                description=description.strip(),
                cves=sorted(list(set(cves)))
            )
        except Exception as e:
            self._logger.error(
                f"Error retrieving module details for {module_path}: {e}"
            )
            return MetasploitModuleDetails(description="", cves=[])
