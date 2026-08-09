import asyncio
from langchain_mcp_adapters.client import MultiServerMCPClient
import sys
import argparse
import os
import logging
from typing import Optional, Tuple
from models import CLIArguments, GuidelineStatus, Software
from repositories import (
    SQLiteMSFModuleRepository,
    SQLiteSoftwareRepository,
    SQLiteOSGuidelineRepository,
    SQLiteSoftwareGuidelineRepository,
    SQLiteTargetSystemRepository,
)
from database import SQLiteDatabaseManager
from services import (
    OSGuidelineService,
    SoftwareGuidelineService,
    MetasploitRPCService,
    MSFModuleService,
    SoftwareService,
    MarkdownBlueprintService,
    CLIAnalyticsService,
    DefaultMSFModuleService,
    DefaultSoftwareService,
    DefaultOSGuidelineService,
    DefaultSoftwareGuidelineService,
)
from agents import (
    VulnerabilityTargetExtractorAgent,
    OSGuidelineGeneratorAgent,
    SoftwareGuidelineGeneratorAgent,
)
from config import settings
from utils import configure_logging, safe_print


def validate_date_format(date_str: str) -> str:
    """
    Validates that a date string is in the format YYYY-MM-DD.
    """
    import re

    if not re.match(r"^\d{4}-\d{2}-\d{2}$", date_str):
        raise argparse.ArgumentTypeError(
            f"Invalid date format: '{date_str}'. Expected YYYY-MM-DD."
        )
    return date_str


def parse_args() -> CLIArguments:
    parser = argparse.ArgumentParser(
        prog="vulnprint",
        description="Vulnprint - Vulnerability Intelligence Analytics & Lab Blueprint Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # Query Metasploit framework and generate lab blueprints:
  python src/main.py search "apache tomcat" -l 5

  # Search local database for Apache vulnerabilities:
  python src/main.py db search "apache*" -p linux -r excellent -o reports/apache_linux.txt

  # View terminal ASCII analytics dashboard:
  python src/main.py db analytics
  python src/main.py analytics

  # View software catalog & summary:
  python src/main.py db list
  python src/main.py db summary

  # Interactively review unverified VM guidelines:
  python src/main.py review

  # Export a VM installation guideline by VM ID or module path:
  python src/main.py export guide 1 -o reports/tomcat_guide.md
  python src/main.py export guide "exploit/multi/http/tomcat_mgr_deploy" -o reports/tomcat_guide.md

  # Export consolidated VM guideline by OS Guideline ID:
  python src/main.py export os 1 -o reports/os_guide.md
""",
    )

    subparsers = parser.add_subparsers(
        dest="command", title="commands", help="Available subcommands"
    )

    # -------------------------------------------------------------
    # Subcommand: search
    # -------------------------------------------------------------
    search_parser = subparsers.add_parser(
        "search",
        help="Query active Metasploit framework module registry and generate lab blueprints",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python src/main.py search "apache tomcat" --limit 5
  python src/main.py search "type:exploit platform:linux" --min-date 2025-01-01 --sort-date desc
""",
    )
    search_parser.add_argument(
        "query",
        type=str,
        help="Search query term or Metasploit filter (e.g., 'apache tomcat', 'type:exploit platform:linux')",
    )
    search_parser.add_argument(
        "-l",
        "--limit",
        type=int,
        help="Cap the maximum number of Metasploit modules to ingest and parse",
    )
    search_parser.add_argument(
        "--min-date",
        type=validate_date_format,
        help="Filter search results by minimum disclosure date (YYYY-MM-DD)",
    )
    search_parser.add_argument(
        "--max-date",
        type=validate_date_format,
        help="Filter search results by maximum disclosure date (YYYY-MM-DD)",
    )
    search_parser.add_argument(
        "--sort-date",
        type=str,
        choices=["asc", "desc"],
        help="Sort search results by disclosure date ('asc' or 'desc')",
    )

    # -------------------------------------------------------------
    # Subcommand: db
    # -------------------------------------------------------------
    db_parser = subparsers.add_parser(
        "db",
        help="Query local database ledger, view analytics, catalog, and software summary",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python main.py db search "apache*" --platform linux --rank excellent -o reports/apache.txt
  python main.py db analytics -o reports/metrics.md
  python main.py db summary
  python main.py db list
""",
    )
    db_parser.add_argument(
        "-o",
        "--output",
        "--export",
        dest="output",
        type=str,
        help="File path to save output reports as Markdown/text",
    )
    db_subparsers = db_parser.add_subparsers(
        dest="subcommand", title="database actions", help="Available database actions"
    )

    # db search
    db_search_parser = db_subparsers.add_parser(
        "search",
        help="Search vulnerability profiles in local database with SQL wildcard support",
    )
    db_search_parser.add_argument(
        "pattern",
        nargs="?",
        default=None,
        type=str,
        help="Wildcard search pattern for software (e.g. 'apache*')",
    )
    db_search_parser.add_argument(
        "-p",
        "--platform",
        type=str,
        help="Filter search results by target OS platform (e.g. linux, windows)",
    )
    db_search_parser.add_argument(
        "-r",
        "--rank",
        type=str,
        help="Filter search results by exploit reliability rank (e.g. excellent, great)",
    )
    db_search_parser.add_argument(
        "--min-date",
        type=validate_date_format,
        help="Filter search results by minimum disclosure date (YYYY-MM-DD)",
    )
    db_search_parser.add_argument(
        "--max-date",
        type=validate_date_format,
        help="Filter search results by maximum disclosure date (YYYY-MM-DD)",
    )
    db_search_parser.add_argument(
        "-m",
        "--msf-path",
        type=str,
        help="Filter search results by Metasploit module path (pattern matching supported, e.g. 'cve', 'exploit/multi/*')",
    )
    db_search_parser.add_argument(
        "-o",
        "--output",
        "--export",
        dest="output",
        type=str,
        help="File path to save search results",
    )

    # db analytics
    db_analytics_parser = db_subparsers.add_parser(
        "analytics",
        help="Generate ASCII metrics panels, technology distributions, and VM guideline coverage statistics",
    )
    db_analytics_parser.add_argument(
        "-o",
        "--output",
        "--export",
        dest="output",
        type=str,
        help="File path to save analytics report as Markdown",
    )

    # db summary
    db_subparsers.add_parser(
        "summary",
        help="Generate summary of target technology counts and percentages from local database",
    )

    # db list
    db_list_parser = db_subparsers.add_parser(
        "list",
        help="Display all unique software products cataloged in the local database",
    )
    db_list_parser.add_argument(
        "-o",
        "--output",
        "--export",
        dest="output",
        type=str,
        help="File path to save software list as Markdown",
    )

    # -------------------------------------------------------------
    # Subcommand: analytics (shortcut for db analytics)
    # -------------------------------------------------------------
    analytics_parser = subparsers.add_parser(
        "analytics",
        help="Display comprehensive ASCII metrics panels & statistics (shortcut for 'db analytics')",
    )
    analytics_parser.add_argument(
        "-o",
        "--output",
        "--export",
        dest="output",
        type=str,
        help="File path to save analytics report as Markdown",
    )

    # -------------------------------------------------------------
    # Subcommand: review
    # -------------------------------------------------------------
    subparsers.add_parser(
        "review",
        help="Start interactive review workflow to approve, modify, or reject unverified guidelines",
    )

    # -------------------------------------------------------------
    # Subcommand: export
    # -------------------------------------------------------------
    export_parser = subparsers.add_parser(
        "export",
        help="Retrieve and export VM installation guidelines",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python main.py export guide 1 -o reports/tomcat_guide.md
  python main.py export guide "exploit/multi/http/tomcat_mgr_deploy" -o reports/tomcat_mgr.md
  python main.py export os 1 -o reports/os_guide.md
""",
    )
    export_parser.add_argument(
        "-o",
        "--output",
        "--export",
        dest="output",
        type=str,
        help="File path to save exported guideline as Markdown",
    )
    export_subparsers = export_parser.add_subparsers(
        dest="subcommand", title="export actions", help="Guideline export type"
    )

    # export guide
    export_guide_parser = export_subparsers.add_parser(
        "guide",
        help="Export VM installation guideline by Metasploit module path or unique database VM ID",
    )
    export_guide_parser.add_argument(
        "target",
        type=str,
        help="Metasploit module path or integer VM ID",
    )
    export_guide_parser.add_argument(
        "-o",
        "--output",
        "--export",
        dest="output",
        type=str,
        help="File path to save exported guideline as Markdown",
    )

    # export os
    export_os_parser = export_subparsers.add_parser(
        "os",
        help="Export consolidated VM installation guideline for an OS guideline ID",
    )
    export_os_parser.add_argument(
        "os_id",
        type=int,
        help="Unique OS Guideline ID",
    )
    export_os_parser.add_argument(
        "-o",
        "--output",
        "--export",
        dest="output",
        type=str,
        help="File path to save exported guideline as Markdown",
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "db" and not args.subcommand:
        db_parser.print_help()
        sys.exit(0)

    if args.command == "export" and not args.subcommand:
        export_parser.print_help()
        sys.exit(0)

    return CLIArguments(
        command=args.command,
        subcommand=getattr(args, "subcommand", None),
        query=getattr(args, "query", None),
        pattern=getattr(args, "pattern", None),
        target=getattr(args, "target", None),
        os_id=getattr(args, "os_id", None),
        platform=getattr(args, "platform", None),
        rank=getattr(args, "rank", None),
        output=getattr(args, "output", None),
        limit=getattr(args, "limit", None),
        min_date=getattr(args, "min_date", None),
        max_date=getattr(args, "max_date", None),
        sort_date=getattr(args, "sort_date", None),
        msf_path=getattr(args, "msf_path", None),
    )


def setup_database_and_services(
    db_path: str,
) -> Tuple[
    MSFModuleService,
    SoftwareService,
    OSGuidelineService,
    SoftwareGuidelineService,
]:
    # Initialize database schema using DatabaseManager
    db_manager = SQLiteDatabaseManager(db_path=db_path)
    db_manager.initialize_schema()

    # Instantiate repositories
    msf_repo = SQLiteMSFModuleRepository(db_manager=db_manager)
    software_repo = SQLiteSoftwareRepository(db_manager=db_manager)
    os_guide_repo = SQLiteOSGuidelineRepository(db_manager=db_manager)
    sw_guide_repo = SQLiteSoftwareGuidelineRepository(db_manager=db_manager)
    target_system_repo = SQLiteTargetSystemRepository(db_manager=db_manager)

    # Wrap repositories in Domain Services
    msf_service = DefaultMSFModuleService(
        msf_repo=msf_repo, software_repo=software_repo
    )
    soft_service = DefaultSoftwareService(
        software_repo=software_repo, target_system_repo=target_system_repo
    )
    os_guide_service = DefaultOSGuidelineService(
        os_guide_repo=os_guide_repo, target_system_repo=target_system_repo
    )
    sw_guide_service = DefaultSoftwareGuidelineService(sw_guide_repo=sw_guide_repo)

    return msf_service, soft_service, os_guide_service, sw_guide_service


def handle_review_mode(
    os_guide_service: OSGuidelineService,
    sw_guide_service: SoftwareGuidelineService,
    soft_service: SoftwareService,
    logger: logging.Logger,
) -> None:
    unverified_guidelines = sw_guide_service.get_unverified_guidelines()
    if not unverified_guidelines:
        logger.info("No unverified Software guidelines found in the database.")
        return

    logger.info(
        f"Found {len(unverified_guidelines)} unverified Software guidelines to review."
    )
    for idx, sw_guide in enumerate(unverified_guidelines, 1):
        path = sw_guide.path
        guideline = sw_guide.guideline

        # Map associated info for display using services and domain models
        software = soft_service.get_software_by_path(path)
        software_name = software.name if software else "Unknown"
        cves = software.cves if software else []

        os_guides = [
            os_guide_service.get_os_guideline_by_id(og_id)
            for og_id in sw_guide.os_guideline_ids
        ]
        os_guides = [og for og in os_guides if og is not None]

        selected_os_guide = None
        if os_guides:
            if len(os_guides) > 1:
                print(f"\nMultiple OS guidelines linked for software guideline {path}:")
                for o_idx, og in enumerate(os_guides, 1):
                    print(f"  [{o_idx}] {og.os_name}")
                while True:
                    try:
                        o_choice = input(
                            f"Select OS Guideline to review [1-{len(os_guides)}] (default 1): "
                        ).strip()
                    except EOFError:
                        selected_os_guide = os_guides[0]
                        break
                    if not o_choice:
                        selected_os_guide = os_guides[0]
                        break
                    if o_choice.isdigit() and 1 <= int(o_choice) <= len(os_guides):
                        selected_os_guide = os_guides[int(o_choice) - 1]
                        break
                    print("Invalid choice.")
            else:
                selected_os_guide = os_guides[0]

        os_name = selected_os_guide.os_name if selected_os_guide else "Unknown OS"
        os_guideline_text = (
            selected_os_guide.guideline
            if selected_os_guide
            else "No OS setup instructions."
        )

        print(f"\n==================================================")
        print(f"[{idx}/{len(unverified_guidelines)}] Reviewing guideline for: {path}")
        print(f"Target Software: {software_name}")
        print(f"Associated CVEs: {cves}")
        print(f"--------------------------------------------------")
        print(f"OS Setup Guideline ({os_name}):")
        print(os_guideline_text)
        print(f"--------------------------------------------------")
        print(f"Software Installation Guideline:")
        print(guideline)
        print(f"--------------------------------------------------")

        while True:
            choice = (
                input(
                    "Select Action: [1] Approve, [2] Modify, [3] Reject, [4] Skip, [q] Quit: "
                )
                .strip()
                .lower()
            )
            if choice in ["1", "approve", "a"]:
                sw_guide_service.update_guideline_status(path, GuidelineStatus.VERIFIED)
                logger.info(f"Approved and marked guideline for {path} as VERIFIED.")
                break
            elif choice in ["2", "modify", "m"]:
                # Write guideline to a temp file
                root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                temp_dir = os.path.join(root_dir, "scratch")
                os.makedirs(temp_dir, exist_ok=True)
                temp_file = os.path.join(
                    temp_dir,
                    f"temp_guideline_{path.replace('/', '_').replace('\\', '_')}.md",
                )

                with open(temp_file, "w", encoding="utf-8") as tf:
                    tf.write(guideline)

                logger.info(
                    f"Opening notepad to modify guideline. Please edit, save, and close the file."
                )
                # Open notepad on Windows, fallback to standard subprocess or terminal wait
                try:
                    import subprocess

                    subprocess.run(["notepad.exe", temp_file], check=True)
                except Exception as editor_err:
                    logger.warning(
                        f"Failed to launch notepad.exe: {editor_err}. Please manually edit the temp file: {temp_file}"
                    )
                    input("Press Enter once you have edited and saved the file...")

                # Read back modified content
                if os.path.exists(temp_file):
                    with open(temp_file, "r", encoding="utf-8") as tf:
                        modified_guideline = tf.read()

                    sw_guide_service.update_guideline_status(
                        path, GuidelineStatus.VERIFIED, modified_guideline
                    )
                    logger.info(
                        f"Marked guideline for {path} as VERIFIED with your modifications."
                    )
                    try:
                        os.remove(temp_file)
                    except Exception:
                        pass
                else:
                    logger.error("Temporary file not found. Skipping modification.")
                break
            elif choice in ["3", "reject", "r"]:
                sw_guide_service.update_guideline_status(path, GuidelineStatus.REJECTED)
                logger.info(f"Marked guideline for {path} as REJECTED.")
                break
            elif choice in ["4", "skip", "s"]:
                logger.info("Skipped.")
                break
            elif choice in ["q", "quit"]:
                logger.info("Exiting review loop.")
                return
            else:
                print("Invalid choice. Please select 1, 2, 3, 4, or q.")


def handle_export_guide_mode(
    os_guide_service: OSGuidelineService,
    sw_guide_service: SoftwareGuidelineService,
    export_guide_path: str,
    export_file_path: Optional[str],
    logger: logging.Logger,
) -> None:
    sw_guidelines = []
    if export_guide_path.isdigit():
        sw_guide = sw_guide_service.get_software_guideline(int(export_guide_path))
        if sw_guide:
            sw_guidelines.append(sw_guide)
    else:
        sw_guidelines = sw_guide_service.get_software_guidelines_by_path(
            export_guide_path
        )

    if not sw_guidelines:
        logger.error(f"No Software guidelines found for: {export_guide_path}")
        return

    output_parts = []
    for sw_guide in sw_guidelines:
        os_guides = [
            os_guide_service.get_os_guideline_by_id(og_id)
            for og_id in sw_guide.os_guideline_ids
        ]
        os_guides = [og for og in os_guides if og is not None]

        selected_os_guide = None
        if os_guides:
            if len(os_guides) > 1:
                print(
                    f"\nMultiple OS guidelines linked to software guideline (ID: {sw_guide.id}):"
                )
                for o_idx, og in enumerate(os_guides, 1):
                    print(f"  [{o_idx}] {og.os_name}")
                while True:
                    try:
                        o_choice = input(
                            f"Select OS Guideline to export [1-{len(os_guides)}] (default 1): "
                        ).strip()
                    except EOFError:
                        selected_os_guide = os_guides[0]
                        break
                    if not o_choice:
                        selected_os_guide = os_guides[0]
                        break
                    if o_choice.isdigit() and 1 <= int(o_choice) <= len(os_guides):
                        selected_os_guide = os_guides[int(o_choice) - 1]
                        break
                    print("Invalid choice.")
            else:
                selected_os_guide = os_guides[0]

        os_name = selected_os_guide.os_name if selected_os_guide else "Unknown OS"
        os_text = (
            selected_os_guide.guideline
            if selected_os_guide
            else "No OS setup instructions."
        )
        output_parts.append(
            f"# VM Installation Guideline for: {sw_guide.path} (ID: {sw_guide.id})\n"
            f"Verification Status: {sw_guide.status.value}\n\n"
            f"## 🖥️ Operating System Setup ({os_name})\n"
            f"{os_text}\n\n"
            f"## 💿 Software Installation\n"
            f"{sw_guide.guideline}\n"
        )
    output_text = "\n---\n\n".join(output_parts)

    if export_file_path:
        try:
            export_dir = os.path.dirname(export_file_path)
            if export_dir and not os.path.exists(export_dir):
                os.makedirs(export_dir, exist_ok=True)
            with open(export_file_path, "w", encoding="utf-8") as ef:
                ef.write(output_text)
            logger.info(f"Successfully exported VM guideline to: {export_file_path}")
        except Exception as e:
            logger.error(f"Error exporting VM guideline to {export_file_path}: {e}")
    else:
        print("\n--------------------------------------------------")
        safe_print(output_text)
        print("--------------------------------------------------")


def handle_export_guideline_by_os_mode(
    os_guide_service: OSGuidelineService,
    sw_guide_service: SoftwareGuidelineService,
    soft_service: SoftwareService,
    export_guideline_by_os_id: str,
    export_file_path: Optional[str],
    logger: logging.Logger,
) -> None:
    if not export_guideline_by_os_id.isdigit():
        logger.error("OS Guideline ID must be an integer.")
        return

    os_id = int(export_guideline_by_os_id)
    os_guide = os_guide_service.get_os_guideline_by_id(os_id)
    if not os_guide:
        logger.error(f"No OS Guideline found for ID: {os_id}")
        return

    # Fetch all software guidelines using this OS Guideline ID
    sw_guidelines = sw_guide_service.get_software_guidelines_by_os_id(os_id)

    os_name = os_guide.os_name
    os_text = os_guide.guideline

    output_parts = [
        f"# VM Installation Guideline (Consolidated for OS ID: {os_id})\n\n",
        f"## 🖥️ Operating System Setup ({os_name})\n\n",
        f"{os_text}\n\n",
        f"## 💿 Software Installation\n\n",
    ]

    if not sw_guidelines:
        output_parts.append(
            "No software installations are associated with this OS Guideline yet.\n"
        )
    else:
        from collections import OrderedDict

        grouped = OrderedDict()
        for sw_guide in sw_guidelines:
            software = soft_service.get_software_by_id(sw_guide.software_id)
            software_name = software.name if software else "Unknown Software"
            grouped.setdefault(software_name, []).append(sw_guide)

        for idx, (software_name, guidelines) in enumerate(grouped.items(), 1):
            if len(guidelines) == 1:
                sw_guide = guidelines[0]
                output_parts.append(
                    f"### {idx}. Software: {software_name} (Path: `{sw_guide.path}`)\n"
                    f"- **Software Guideline ID:** {sw_guide.id}\n"
                    f"- **Verification Status:** {sw_guide.status.value}\n\n"
                    f"{sw_guide.guideline}\n\n"
                )
            else:
                output_parts.append(f"### {idx}. Software: {software_name}\n")
                output_parts.append(
                    f"Multiple vulnerability profiles and configurations are registered for this software under the target OS. "
                    f"Please follow the setup instructions for the specific Metasploit module path you are deploying:\n\n"
                )
                for sw_guide in guidelines:
                    output_parts.append(
                        f"#### 📦 Module: `{sw_guide.path}`\n"
                        f"- **Software Guideline ID:** {sw_guide.id}\n"
                        f"- **Verification Status:** {sw_guide.status.value}\n\n"
                        f"{sw_guide.guideline}\n\n"
                    )
            output_parts.append("---\n\n")

    output_text = "".join(output_parts).rstrip("\n-") + "\n"

    if export_file_path:
        try:
            export_dir = os.path.dirname(export_file_path)
            if export_dir and not os.path.exists(export_dir):
                os.makedirs(export_dir, exist_ok=True)
            with open(export_file_path, "w", encoding="utf-8") as ef:
                ef.write(output_text)
            logger.info(
                f"Successfully exported consolidated guideline to: {export_file_path}"
            )
        except Exception as e:
            logger.error(
                f"Error exporting consolidated guideline to {export_file_path}: {e}"
            )
    else:
        print("\n--------------------------------------------------")
        safe_print(output_text)
        print("--------------------------------------------------")


def handle_analytics_mode(
    args: CLIArguments,
    msf_service: MSFModuleService,
    soft_service: SoftwareService,
    sw_guide_service: SoftwareGuidelineService,
    os_guide_service: OSGuidelineService,
) -> None:
    from services import DefaultVMGuidelineService

    vm_guide_service = DefaultVMGuidelineService(
        os_guide_service=os_guide_service,
        sw_guide_service=sw_guide_service,
    )
    analytics_service = CLIAnalyticsService(
        msf_service=msf_service,
        soft_service=soft_service,
        sw_guide_service=sw_guide_service,
        os_guide_service=os_guide_service,
        vm_guide_service=vm_guide_service,
    )
    if args.command == "db" and args.subcommand == "summary":
        analytics_service.display_dashboard()
    elif args.command == "analytics" or (
        args.command == "db" and args.subcommand == "analytics"
    ):
        analytics_service.display_analytics(export_path=args.output)
    elif args.command == "db" and args.subcommand == "list":
        analytics_service.display_software_list(export_path=args.output)
    elif args.command == "db" and args.subcommand == "search":
        analytics_service.display_search_results(
            software_pattern=args.pattern,
            platform=args.platform,
            rank=args.rank,
            min_date=args.min_date,
            max_date=args.max_date,
            msf_path=args.msf_path,
            export_path=args.output,
        )


async def handle_search_ingestion(
    args: CLIArguments,
    msf_service: MSFModuleService,
    soft_service: SoftwareService,
    os_guide_service: OSGuidelineService,
    sw_guide_service: SoftwareGuidelineService,
    logger: logging.Logger,
) -> None:
    if not settings.msf_rpc_password:
        logger.error(
            "Critical Error: MSF_RPC_PASSWORD environment variable is not defined. "
            "Please create a .env file containing the secure Metasploit RPC password."
        )
        sys.exit(1)

    logger.info(
        f"Connecting to Metasploit RPC Daemon at {settings.msf_rpc_host}:{settings.msf_rpc_port}..."
    )
    metasploit_service = MetasploitRPCService(
        host=settings.msf_rpc_host,
        port=settings.msf_rpc_port,
        password=settings.msf_rpc_password,
        ssl=True,
    )
    try:
        metasploit_service.connect()
    except Exception:
        sys.exit(1)

    # Initialize agents
    logger.info("Initializing AI agents...")

    try:
        tools = await MultiServerMCPClient(
            {
                "mcp_search": {
                    "transport": "http",
                    "url": settings.mcp_search_url,
                }
            }
        ).get_tools()
    except Exception as e:
        logger.warning(f"Error initializing MCP tools: {e}")
        tools = []

    extractor = VulnerabilityTargetExtractorAgent(
        tools=tools,
        max_tool_calls=settings.mcp_max_tool_calls,
        ai_base_url=settings.ai_base_url,
        ai_api_key=settings.ai_api_key,
        ai_model=settings.ai_model,
        temperature=settings.ai_model_temperature,
    )
    os_guideline_generator_agent = OSGuidelineGeneratorAgent(
        msf_service=msf_service,
        soft_service=soft_service,
    )
    software_guideline_generator_agent = SoftwareGuidelineGeneratorAgent(
        msf_service=msf_service,
        soft_service=soft_service,
        os_guide_service=os_guide_service,
        ai_base_url=settings.ai_base_url,
        ai_api_key=settings.ai_api_key,
        ai_model=settings.ai_model,
        tools=tools,
        max_tool_calls=settings.mcp_max_tool_calls,
        temperature=settings.ai_model_temperature,
    )

    # Initialize blueprint service
    blueprint_service = MarkdownBlueprintService(
        msf_service=msf_service,
        soft_service=soft_service,
        output_dir=settings.blueprints_dir,
        os_guide_service=os_guide_service,
        sw_guide_service=sw_guide_service,
        os_guideline_generator_agent=os_guideline_generator_agent,
        software_guideline_generator_agent=software_guideline_generator_agent,
    )

    logger.info(f"Executing search query: '{args.query}'")
    module_paths = metasploit_service.search_modules(
        args.query,
        min_date=args.min_date,
        max_date=args.max_date,
        sort_by_date=args.sort_date,
    )
    if not module_paths:
        logger.warning("No exploit modules matched the search query.")
        return
    logger.info(f"Found {len(module_paths)} matching exploit modules.")

    # Apply module cap limit
    if args.limit and args.limit > 0:
        logger.info(
            f"Limiting Metasploit module processing to the top {args.limit} results."
        )
        module_paths = module_paths[: args.limit]

    success_count = 0
    for idx, path in enumerate(module_paths, 1):
        logger.info(f"[{idx}/{len(module_paths)}] Processing: {path}")

        # Fetch module details from Metasploit
        module_details = metasploit_service.get_module_details(path)
        desc = module_details.description
        if not desc or len(desc.strip()) == 0:
            logger.warning(
                f"[{idx}/{len(module_paths)}] Module description is empty. Skipping model analysis."
            )
        else:
            logger.info(
                f"[{idx}/{len(module_paths)}] Interrogating AI model ({settings.ai_model}) to extract software metadata..."
            )
            vuln_target = await extractor.extract(
                description=desc,
                documentation=module_details.documentation,
                cves=module_details.cves,
                msf_path=path,
                msf_module_name=module_details.module_name,
                target_platforms=module_details.platform,
            )

            if vuln_target is None:
                logger.warning(
                    f"[{idx}/{len(module_paths)}] Failed to extract software metadata. Skipping..."
                )
                continue

        logger.info(
            f"[{idx}/{len(module_paths)}] Recording intelligence in database ledger..."
        )

        msf_service.store_module(module_details)
        soft_service.store_software(
            Software(
                path=path,
                cves=module_details.cves,
                vulnerable_versions=vuln_target.vulnerable_versions,
                required_configs=vuln_target.required_configs,
                name=vuln_target.software_name,
                platform=vuln_target.platform,
                distribution=vuln_target.os_distribution_or_edition,
                version=vuln_target.os_version_or_release,
                architecture=vuln_target.os_architecture,
            )
        )

        # Generate Markdown Lab Blueprint Manual
        blueprint_file = await blueprint_service.generate_blueprint(path)
        if blueprint_file:
            logger.info(
                f"[{idx}/{len(module_paths)}] Saved Lab Blueprint Manual to: {blueprint_file}"
            )
            success_count += 1
        else:
            logger.error(
                f"[{idx}/{len(module_paths)}] Failed to generate blueprint manual."
            )

    logger.info(
        f"Ingestion Complete! Successfully processed and generated {success_count} manuals."
    )


def main():
    # Initialize logging system
    configure_logging(settings.log_level)
    logger = logging.getLogger("main")

    # CLI Argument Parsing Setup
    args = parse_args()

    logger.info("Initializing database and services...")
    msf_service, soft_service, os_guide_service, sw_guide_service = (
        setup_database_and_services(
            db_path=settings.database_path,
        )
    )

    # Route based on command/subcommand
    if args.command == "review":
        handle_review_mode(os_guide_service, sw_guide_service, soft_service, logger)
    elif args.command == "export":
        if args.subcommand == "guide":
            handle_export_guide_mode(
                os_guide_service=os_guide_service,
                sw_guide_service=sw_guide_service,
                export_guide_path=args.target,
                export_file_path=args.output,
                logger=logger,
            )
        elif args.subcommand == "os":
            handle_export_guideline_by_os_mode(
                os_guide_service=os_guide_service,
                sw_guide_service=sw_guide_service,
                soft_service=soft_service,
                export_guideline_by_os_id=str(args.os_id),
                export_file_path=args.output,
                logger=logger,
            )
    elif args.command in ["db", "analytics"]:
        handle_analytics_mode(
            args, msf_service, soft_service, sw_guide_service, os_guide_service
        )
    elif args.command == "search":
        asyncio.run(
            handle_search_ingestion(
                args=args,
                msf_service=msf_service,
                soft_service=soft_service,
                os_guide_service=os_guide_service,
                sw_guide_service=sw_guide_service,
                logger=logger,
            )
        )


if __name__ == "__main__":
    main()
