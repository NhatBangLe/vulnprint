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
from agents import VulnerabilityTargetExtractorAgent, VMGuidelineGeneratorAgent
from config import settings
from utils import configure_logging


def parse_args() -> CLIArguments:
    parser = argparse.ArgumentParser(
        description="Vulnprint - Vulnerability Intelligence & Lab Blueprint Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # Search Metasploit, run search agent and build blueprints (limit to 5):
  python src/main.py --search "apache tomcat" --limit 5

  # Interactively review all unverified VM guidelines in the database:
  python src/main.py --review

  # Export the VM guideline for a specific Metasploit path:
  python src/main.py --export-guide "exploit/multi/http/tomcat_mgr_deploy" --export reports/tomcat_mgr.md

  # Export the VM guideline using its unique database VM ID:
  python src/main.py --export-guide 1 --export reports/tomcat_guide_v1.md

  # Show basic software vulnerability counts:
  python src/main.py --summary

  # Show detailed metrics:
  python src/main.py --analytics

  # List all unique software targets in the database:
  python src/main.py --list-software

  # Search local database for Apache vulnerabilities with Linux platform & excellent rank filter, and export output:
  python src/main.py --search-db "apache*" --platform "linux" --rank "excellent" --export reports/apache_linux_excellent.txt
""",
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--search",
        type=str,
        help="Query active Metasploit framework module registry and generate new lab blueprints",
    )
    group.add_argument(
        "--analytics",
        action="store_true",
        help="Generate comprehensive ASCII metrics panels, technology distributions, and VM guideline coverage statistics",
    )
    group.add_argument(
        "--summary",
        action="store_true",
        help="Generate summary of target technology counts and percentages from local database",
    )
    group.add_argument(
        "--list-software",
        action="store_true",
        help="Display all unique software products cataloged in the local database",
    )
    group.add_argument(
        "--search-db",
        type=str,
        help="Search vulnerability profiles in local database with SQL wildcard support",
    )
    group.add_argument(
        "--review",
        action="store_true",
        help="Start interactive review workflow to approve, modify, or reject unverified guidelines",
    )
    group.add_argument(
        "--export-guide",
        type=str,
        help="Retrieve and output a VM installation guideline by Metasploit path or unique VM ID",
    )

    # Optional filters and options
    parser.add_argument(
        "--platform",
        type=str,
        help="Filter database searches/queries by target OS platform (e.g. linux, windows)",
    )
    parser.add_argument(
        "--rank",
        type=str,
        help="Filter database searches/queries by exploit reliability rank (e.g. excellent, great)",
    )
    parser.add_argument(
        "--export",
        type=str,
        help="File path to save output reports, list details, or guidelines as Markdown",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="Cap the maximum number of Metasploit modules to ingest and parse per search",
    )

    args = parser.parse_args()
    return CLIArguments(
        search=args.search,
        analytics=args.analytics,
        summary=args.summary,
        list_software=args.list_software,
        search_db=args.search_db,
        platform=args.platform,
        rank=args.rank,
        export=args.export,
        limit=args.limit,
        review=args.review,
        export_guide=args.export_guide,
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

    # Wrap repositories in Domain Services
    msf_service = DefaultMSFModuleService(
        msf_repo=msf_repo, software_repo=software_repo
    )
    soft_service = DefaultSoftwareService(software_repo=software_repo)
    os_guide_service = DefaultOSGuidelineService(os_guide_repo=os_guide_repo)
    sw_guide_service = DefaultSoftwareGuidelineService(sw_guide_repo=sw_guide_repo)

    return msf_service, soft_service, os_guide_service, sw_guide_service


def handle_review_mode(
    os_guide_service: OSGuidelineService,
    sw_guide_service: SoftwareGuidelineService,
    soft_service: SoftwareService,
    msf_service: MSFModuleService,
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

        os_guide = os_guide_service.get_os_guideline_by_id(sw_guide.os_guideline_id)
        os_name = os_guide.os_name if os_guide else "Unknown OS"
        os_guideline_text = (
            os_guide.guideline if os_guide else "No OS setup instructions."
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
        os_guide = os_guide_service.get_os_guideline_by_id(sw_guide.os_guideline_id)
        os_name = os_guide.os_name if os_guide else "Unknown OS"
        os_text = os_guide.guideline if os_guide else "No OS setup instructions."
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
        print(output_text)
        print("--------------------------------------------------")


def handle_analytics_mode(
    args: CLIArguments,
    msf_service: MSFModuleService,
    soft_service: SoftwareService,
    sw_guide_service: SoftwareGuidelineService,
) -> None:
    analytics_service = CLIAnalyticsService(
        msf_service=msf_service,
        soft_service=soft_service,
        sw_guide_service=sw_guide_service,
    )
    if args.summary:
        analytics_service.display_dashboard()
    elif args.analytics:
        analytics_service.display_analytics(export_path=args.export)
    elif args.list_software:
        analytics_service.display_software_list(export_path=args.export)
    elif args.search_db:
        analytics_service.display_search_results(
            software_pattern=args.search_db,
            platform=args.platform,
            rank=args.rank,
            export_path=args.export,
        )


def handle_search_ingestion(
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
    tools = asyncio.run(
        MultiServerMCPClient(
            {
                "mcp_search": {
                    "transport": "http",
                    "url": settings.mcp_search_url,
                }
            }
        ).get_tools()
    )
    extractor = VulnerabilityTargetExtractorAgent(
        tools=tools,
        ai_base_url=settings.ai_base_url,
        ai_api_key=settings.ai_api_key,
        ai_model=settings.ai_model,
    )
    vm_guideline_generator_agent = VMGuidelineGeneratorAgent(
        msf_service=msf_service,
        soft_service=soft_service,
        ai_base_url=settings.ai_base_url,
        ai_api_key=settings.ai_api_key,
        ai_model=settings.ai_model,
        tools=tools,
        max_tool_calls=settings.mcp_max_tool_calls,
    )

    # Initialize blueprint service
    blueprint_service = MarkdownBlueprintService(
        msf_service=msf_service,
        soft_service=soft_service,
        output_dir=settings.blueprints_dir,
        os_guide_service=os_guide_service,
        sw_guide_service=sw_guide_service,
        vm_guideline_generator_agent=vm_guideline_generator_agent,
    )

    logger.info(f"Executing search query: '{args.search}'")
    module_paths = metasploit_service.search_modules(args.search)
    if not module_paths:
        logger.warning(
            "No exploit modules matched the search query or buffer read failed."
        )
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
            slm_data = extractor.extract(
                description=desc, documentation=module_details.documentation
            )

            if slm_data is None:
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
                vulnerable_versions=slm_data.vulnerable_versions,
                required_configs=slm_data.required_configs,
                name=slm_data.software_name,
            )
        )

        # Generate Markdown Lab Blueprint Manual
        blueprint_file = blueprint_service.generate_blueprint(path)
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

    # Route based on command/mode
    if (
        args.analytics
        or args.summary
        or args.list_software
        or args.search_db
        or args.review
        or args.export_guide
    ):
        if args.review:
            handle_review_mode(
                os_guide_service, sw_guide_service, soft_service, msf_service, logger
            )
        elif args.export_guide:
            handle_export_guide_mode(
                os_guide_service=os_guide_service,
                sw_guide_service=sw_guide_service,
                export_guide_path=args.export_guide,
                export_file_path=args.export,
                logger=logger,
            )
        else:
            handle_analytics_mode(args, msf_service, soft_service, sw_guide_service)
    elif args.search:
        handle_search_ingestion(
            args=args,
            msf_service=msf_service,
            soft_service=soft_service,
            os_guide_service=os_guide_service,
            sw_guide_service=sw_guide_service,
            logger=logger,
        )


if __name__ == "__main__":
    main()
