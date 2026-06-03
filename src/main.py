import sys
import argparse
import os
import logging

try:
    from src.models import CLIArguments, ExploitDetails
    from src.metasploit import MetasploitRPCService
    from src.ai_parser import LLMVulnerabilityMetadataExtractor
    from src.database import SQLiteVulnerabilityRepository
    from src.blueprint import MarkdownBlueprintService
    from src.analytics import CLIAnalyticsService
    from src.config import settings
    from src.utils import configure_logging
except ImportError:
    from models import CLIArguments, ExploitDetails
    from metasploit import MetasploitRPCService
    from ai_parser import LLMVulnerabilityMetadataExtractor
    from database import SQLiteVulnerabilityRepository
    from blueprint import MarkdownBlueprintService
    from analytics import CLIAnalyticsService
    from config import settings
    from utils import configure_logging


def parse_args() -> CLIArguments:
    parser = argparse.ArgumentParser(
        description="Vulnprint - Vulnerability Intelligence & Lab Blueprint Engine"
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--search",
        type=str,
        help="Execute query command against Metasploit RPC console and build blueprints",
    )
    group.add_argument(
        "--analytics",
        action="store_true",
        help="Generate ASCII metrics summary dashboard from database ledger",
    )
    group.add_argument(
        "--summary",
        action="store_true",
        help="Generate ASCII metrics summary dashboard from database ledger",
    )

    args = parser.parse_args()
    return CLIArguments(
        search=args.search,
        analytics=args.analytics,
        summary=args.summary,
    )


def main():
    # Initialize logging system
    configure_logging(settings.log_level)
    logger = logging.getLogger("main")

    msf_host = settings.msf_rpc_host
    msf_port = settings.msf_rpc_port
    msf_password = settings.msf_rpc_password

    ai_base_url = settings.ai_base_url
    ai_model = settings.ai_model
    ai_api_key = settings.ai_api_key

    blueprints_dir = settings.blueprints_dir
    db_path = settings.database_path

    # CLI Argument Parsing Setup
    args = parse_args()

    # 1. Option: Dashboard Analytics
    if args.analytics or args.summary:
        if not os.path.exists(db_path):
            logger.warning(
                "Database ledger does not exist. Please query Metasploit first to populate it."
            )
            return

        repository = SQLiteVulnerabilityRepository(db_path=db_path)
        analytics_service = CLIAnalyticsService(repository=repository)
        analytics_service.display_dashboard()
        return

    # 2. Option: Search & Build Blueprints
    if args.search:
        if not msf_password:
            logger.error(
                "Critical Error: MSF_RPC_PASSWORD environment variable is not defined. "
                "Please create a .env file containing the secure Metasploit RPC password."
            )
            sys.exit(1)

        repository = SQLiteVulnerabilityRepository(db_path=db_path)
        logger.info(f"Initializing local database ledger: {db_path}")
        repository.initialize()

        logger.info(f"Connecting to Metasploit RPC Daemon at {msf_host}:{msf_port}...")
        metasploit_service = MetasploitRPCService(
            host=msf_host, port=msf_port, password=msf_password, ssl=True
        )
        try:
            metasploit_service.connect()
        except Exception:
            sys.exit(1)

        extractor = LLMVulnerabilityMetadataExtractor(
            base_url=ai_base_url, api_key=ai_api_key, model_name=ai_model
        )
        blueprint_service = MarkdownBlueprintService(
            repository=repository, output_dir=blueprints_dir
        )

        logger.info(f"Executing search query: '{args.search}'")
        module_paths = metasploit_service.search_modules(args.search)

        if not module_paths:
            logger.warning(
                "No exploit modules matched the search query or buffer read failed."
            )
            return

        logger.info(f"Found {len(module_paths)} matching exploit modules.")

        success_count = 0
        for idx, path in enumerate(module_paths, 1):
            logger.info(f"[{idx}/{len(module_paths)}] Processing: {path}")

            # Fetch module details from Metasploit
            details = metasploit_service.get_module_details(path)
            desc = details.description
            cves = details.cves

            if not desc:
                logger.warning(
                    f"[{idx}/{len(module_paths)}] Module description is empty. Skipping model analysis."
                )
                slm_data = ExploitDetails(
                    software_name="Unknown", vulnerable_versions=[], required_configs=[]
                )
            else:
                logger.info(
                    f"[{idx}/{len(module_paths)}] Interrogating local SLM ({ai_model}) to extract software metadata..."
                )
                slm_data = extractor.extract_metadata(desc, details.documentation)

            # Persist analytics inside repository
            logger.info(
                f"[{idx}/{len(module_paths)}] Recording intelligence in database ledger..."
            )
            repository.store_vulnerability(
                data=slm_data,
                details=details,
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


if __name__ == "__main__":
    main()
