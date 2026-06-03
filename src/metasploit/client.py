from pymetasploit3.msfrpc import ExploitModule
from pymetasploit3.msfrpc import ModuleManager
from pymetasploit3.msfrpc import MsfConsole
from pymetasploit3.msfrpc import ConsoleManager
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

    def __init__(self, host: str, port: int, password: str, ssl=True):
        self.host = host
        self.port = port
        self.password = password
        self.ssl = ssl
        self.client: MsfRpcClient | None = None
        self._logger = logging.getLogger(self.__class__.__name__)

    def connect(self) -> None:
        """
        Initializes and returns an authenticated MsfRpcClient connection.
        """
        try:
            self.client = MsfRpcClient(
                password=self.password, port=self.port, server=self.host, ssl=self.ssl
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

        console_manager: ConsoleManager = self.client.consoles
        console: MsfConsole | None = None
        try:
            # Spawn an active virtual console session
            console: MsfConsole = console_manager.console()

            # Send precise CLI search directive
            command = f"search {search_string}\n"
            console.write(command)

            # Pause explicitly for the buffer to fill
            time.sleep(2)

            # Read the raw console output string
            output_data = console.read()  # dict_keys(['data', 'prompt', 'busy'])
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
            if console is not None:
                try:
                    console.destroy()
                except Exception as destroy_error:
                    self._logger.warning(
                        f"Failed to destroy console session {str(console.cid)}: {destroy_error}"
                    )

    def get_module_details(self, module_path: str) -> MetasploitModuleDetails:
        """
        Retrieves the description, CVE references, metadata, and documentation for a specific module path.
        """
        if not self.client:
            raise RuntimeError("Client is not connected. Call connect() first.")

        try:
            # Load the module
            module_manager: ModuleManager = self.client.modules
            exploit: ExploitModule = module_manager.use("exploit", module_path)
            self._logger.info(exploit.info)

            # Extract metadata properties
            mtype = getattr(exploit, "type", "exploit")
            name = getattr(exploit, "name", "")
            module_name = getattr(exploit, "fullname", module_path)
            rank = str(getattr(exploit, "rank", ""))
            disclosure_date = str(getattr(exploit, "disclosuredate", ""))

            platform_raw = getattr(exploit, "platform", [])
            if isinstance(platform_raw, str):
                platform = [platform_raw]
            elif isinstance(platform_raw, (list, tuple)):
                platform = [str(p) for p in platform_raw]
            else:
                platform = []

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

            # Retrieve and parse documentation from console
            documentation = ""
            filepath = exploit.info.get("filepath")
            if filepath:
                # Construct doc_path
                # Replace 'modules/' with 'documentation/modules/'
                # Replace plural module types to singular, e.g. exploits -> exploit, payloads -> payload, etc.
                doc_path = filepath.replace("modules/", "documentation/modules/")
                doc_path = re.sub(r"/exploits/", "/exploit/", doc_path)
                doc_path = re.sub(r"/payloads/", "/payload/", doc_path)
                doc_path = re.sub(r"/encoders/", "/encoder/", doc_path)
                doc_path = re.sub(r"/nops/", "/nop/", doc_path)
                doc_path = re.sub(r"/evasions/", "/evasion/", doc_path)
                # Replace .rb extension with .md
                if doc_path.endswith(".rb"):
                    doc_path = doc_path[:-3] + ".md"

                # Execute cat on MSF Console
                console_manager: ConsoleManager = self.client.consoles
                console: MsfConsole | None = None
                try:
                    console: MsfConsole = console_manager.console()
                    cmd = f"cat {doc_path}\n"
                    console.write(cmd)

                    # Wait for console buffer to fill
                    time.sleep(2)

                    output_data = (
                        console.read()
                    )  # dict_keys(['data', 'prompt', 'busy'])
                    raw_data = (
                        output_data.get("data", "")
                        if isinstance(output_data, dict)
                        else str(output_data)
                    )

                    if "No such file or directory" not in raw_data and raw_data.strip():
                        lines = raw_data.splitlines()
                        cleaned_lines = []
                        capture = False
                        for line in lines:
                            if "Starting persistent handler(s)..." in line:
                                capture = True
                                continue
                            if capture:
                                if (
                                    line.strip() == cmd.strip()
                                    or line.strip() == "cat " + doc_path
                                ):
                                    continue
                                if re.match(r"^msf\d*\s*>\s*$", line.strip()):
                                    continue
                                cleaned_lines.append(line)

                        if not capture:
                            for line in lines:
                                if (
                                    line.strip() == cmd.strip()
                                    or line.strip() == "cat " + doc_path
                                ):
                                    continue
                                if re.match(r"^msf\d*\s*>\s*$", line.strip()):
                                    continue
                                if "Starting persistent handler(s)..." in line:
                                    continue
                                cleaned_lines.append(line)

                        documentation = "\n".join(cleaned_lines).strip()
                except Exception as console_err:
                    self._logger.warning(
                        f"Failed to retrieve documentation for module {module_path} via console: {console_err}"
                    )
                finally:
                    if console is not None:
                        try:
                            console.destroy()
                        except Exception as destroy_error:
                            self._logger.warning(
                                f"Failed to destroy console session {str(console.cid)}: {destroy_error}"
                            )

            return MetasploitModuleDetails(
                description=description.strip(),
                cves=sorted(list(set(cves))),
                type=mtype,
                name=name,
                module_name=module_name,
                rank=rank,
                disclosure_date=disclosure_date,
                platform=platform,
                documentation=documentation,
            )
        except Exception as e:
            self._logger.error(
                f"Error retrieving module details for {module_path}: {e}"
            )
            return MetasploitModuleDetails(description="", cves=[])
