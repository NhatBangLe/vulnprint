"""
CLI Interface for Vulnprint Evaluation Harness.
"""

import sys
import argparse
from pathlib import Path

# Ensure UTF-8 output encoding on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


# Ensure package imports work whether executed as a script or as a module
if __package__ is None or __package__ == "":
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from evaluation.runner import EvaluationRunner
    from evaluation.turn_manager import TurnManager
    from evaluation.config_manager import (
        EvaluationConfig,
        RunMetadata,
        ModelConfig,
        MetasploitConfig,
        MCPConfig,
        TaskConfig,
        OutputConfig,
        capture_system_info,
        export_config_to_json,
    )
else:
    from .runner import EvaluationRunner
    from .turn_manager import TurnManager
    from .config_manager import (
        EvaluationConfig,
        RunMetadata,
        ModelConfig,
        MetasploitConfig,
        MCPConfig,
        TaskConfig,
        OutputConfig,
        capture_system_info,
        export_config_to_json,
    )


def validate_date_format(date_str: str) -> str:
    """Validates that a date string is in the format YYYY-MM-DD."""
    import re

    if not re.match(r"^\d{4}-\d{2}-\d{2}$", date_str):
        raise argparse.ArgumentTypeError(
            f"Invalid date format: '{date_str}'. Expected YYYY-MM-DD."
        )
    return date_str


def build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnprint-eval",
        description="Vulnprint Evaluation Harness - Benchmark Runner, Environment Exporter & Reproducer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # 1. Run evaluation with default dataset (evaluation_data/msf_paths.json):
  python evaluation/cli.py run

  # 2. Run evaluation with limited modules and specific AI model:
  python evaluation/cli.py run -l 5 --ai-model llama3 --ai-temperature 0.2 --run-name run_llama3_test

  # 3. Run evaluation targeting the project RUN directory:
  python evaluation/cli.py run -f evaluation_data/msf_paths.json -o RUN --run-name RUN_vulprint_4

  # 4. Reproduce a previous evaluation run from its exported config.json:
  python evaluation/cli.py reproduce -c evaluation/runs/run_001/config.json

  # 5. Dry-run reproduction to inspect parameters:
  python evaluation/cli.py reproduce -c evaluation/runs/run_001/config.json --dry-run

  # 6. List all evaluation runs:
  python evaluation/cli.py list
  python evaluation/cli.py list -o RUN

  # 7. Generate a template configuration JSON:
  python evaluation/cli.py export-config -o config.template.json
        """,
    )

    subparsers = parser.add_subparsers(
        dest="command", title="Evaluation Commands", help="Available subcommands"
    )

    # -------------------------------------------------------------
    # Subcommand: run
    # -------------------------------------------------------------
    run_parser = subparsers.add_parser(
        "run",
        help="Run an evaluation session, isolate outputs per turn, and export environment config JSON",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # Task / Dataset options
    run_parser.add_argument(
        "-f",
        "--file",
        "--input-file",
        dest="input_file",
        type=str,
        default=None,
        help="Path to input dataset file (JSON array, JSONL, or text list of MSF module paths). Default: evaluation_data/msf_paths.json",
    )
    run_parser.add_argument(
        "-q",
        "--query",
        type=str,
        default=None,
        help="Optional search query or Metasploit search filter",
    )
    run_parser.add_argument(
        "-l",
        "--limit",
        type=int,
        default=None,
        help="Cap the maximum number of modules to evaluate (e.g. --limit 5)",
    )
    run_parser.add_argument(
        "--min-date",
        type=validate_date_format,
        help="Filter modules by minimum disclosure date (YYYY-MM-DD)",
    )
    run_parser.add_argument(
        "--max-date",
        type=validate_date_format,
        help="Filter modules by maximum disclosure date (YYYY-MM-DD)",
    )
    run_parser.add_argument(
        "--sort-date",
        type=str,
        choices=["asc", "desc"],
        help="Sort modules by disclosure date ('asc' or 'desc')",
    )

    # AI / Model overrides
    run_parser.add_argument(
        "--ai-model",
        type=str,
        help="Override AI model name (e.g. llama3, gpt-4o, claude-3-5-sonnet)",
    )
    run_parser.add_argument(
        "--ai-base-url",
        type=str,
        help="Override AI API base URL (e.g. http://localhost:11434/v1 or https://openrouter.ai/api/v1)",
    )
    run_parser.add_argument(
        "--ai-temperature",
        type=float,
        help="Override LLM sampling temperature (0.0 to 2.0)",
    )
    run_parser.add_argument(
        "--ai-api-key",
        type=str,
        help="Override or provide AI API key",
    )

    # Metasploit RPC overrides
    run_parser.add_argument(
        "--msf-host",
        type=str,
        help="Override Metasploit RPC host (default: 127.0.0.1)",
    )
    run_parser.add_argument(
        "--msf-port",
        type=int,
        help="Override Metasploit RPC port (default: 55553)",
    )
    run_parser.add_argument(
        "--msf-password",
        type=str,
        help="Override Metasploit RPC password",
    )
    run_parser.add_argument(
        "--msf-version",
        type=str,
        default=None,
        help="Optional Metasploit Framework version (e.g. '6.4.15') for tracking purpose",
    )

    # MCP Search overrides
    run_parser.add_argument(
        "--mcp-url",
        type=str,
        help="Override MCP search server URL (default: http://localhost:8000/mcp)",
    )
    run_parser.add_argument(
        "--mcp-max-calls",
        type=int,
        help="Override maximum MCP tool calls",
    )

    # Turn / Output options
    run_parser.add_argument(
        "-o",
        "--output-dir",
        type=str,
        default="evaluation/runs",
        help="Base directory for storing evaluation runs (default: evaluation/runs)",
    )
    run_parser.add_argument(
        "--run-name",
        type=str,
        default=None,
        help="Custom name for the turn directory (e.g. run_001, RUN_vulprint_4). Auto-generated if omitted.",
    )
    run_parser.add_argument(
        "--tag",
        type=str,
        default=None,
        help="Label or description for this evaluation run",
    )
    run_parser.add_argument(
        "--export-secrets",
        action="store_true",
        help="Export raw API keys and passwords into config.json (Default: masked references)",
    )

    # -------------------------------------------------------------
    # Subcommand: reproduce
    # -------------------------------------------------------------
    reproduce_parser = subparsers.add_parser(
        "reproduce",
        help="Reproduce an evaluation from a previously exported config.json",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    reproduce_parser.add_argument(
        "-c",
        "--config",
        type=str,
        required=True,
        help="Path to the exported config.json file to reproduce",
    )
    reproduce_parser.add_argument(
        "-o",
        "--output-dir",
        type=str,
        default="evaluation/runs",
        help="Base directory for storing the reproduced run (default: evaluation/runs)",
    )
    reproduce_parser.add_argument(
        "--run-name",
        type=str,
        default=None,
        help="Custom name for the reproduced turn (defaults to <original_run_name>_reproduced)",
    )
    reproduce_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Display reproduction parameters without actually running the evaluation",
    )
    reproduce_parser.add_argument(
        "--export-secrets",
        action="store_true",
        help="Export raw credentials in the reproduced turn's config.json",
    )

    # -------------------------------------------------------------
    # Subcommand: list
    # -------------------------------------------------------------
    list_parser = subparsers.add_parser(
        "list",
        help="List all recorded evaluation runs and their status",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    list_parser.add_argument(
        "-o",
        "--output-dir",
        type=str,
        default="evaluation/runs",
        help="Base runs directory to inspect (default: evaluation/runs)",
    )

    # -------------------------------------------------------------
    # Subcommand: export-config
    # -------------------------------------------------------------
    export_cfg_parser = subparsers.add_parser(
        "export-config",
        help="Generate a template configuration JSON file without running",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    export_cfg_parser.add_argument(
        "-o",
        "--output",
        type=str,
        default="config.template.json",
        help="File path to save the generated configuration template (default: config.template.json)",
    )

    return parser


def handle_list(output_dir: str):
    """Lists all turns in the target directory."""
    turn_mgr = TurnManager(base_dir=output_dir)
    turns = turn_mgr.list_turns()

    print(f"\n📂 Evaluation Runs in '{output_dir}': ({len(turns)} found)\n")
    if not turns:
        print("  No evaluation runs found.")
        print("  Run 'python evaluation/cli.py run' to start your first evaluation.\n")
        return

    header = f"{'Run Name':<20} | {'Status':<12} | {'Model':<16} | {'Blueprints':<10} | {'DB Size':<10} | {'Duration':<10} | {'Created At':<19}"
    divider = "-" * len(header)
    print(header)
    print(divider)

    for t in turns:
        db_str = f"{t['db_size_kb']} KB" if t["has_db"] else "None"
        bp_str = f"{t['blueprints_count']} files" if t["has_blueprints"] else "None"
        print(
            f"{t['name']:<20} | {t['status']:<12} | {t['model']:<16} | {bp_str:<10} | {db_str:<10} | {t['duration_seconds']:<10} | {t['created_at']:<19}"
        )
    print(divider + "\n")


def handle_export_config_template(output_path: str):
    """Creates a sample configuration template."""
    sys_info = capture_system_info()
    template_config = EvaluationConfig(
        version="1.0.0",
        metadata=RunMetadata(
            run_id="run_template_sample",
            run_name="run_sample",
            tag="Baseline evaluation template",
            status="pending",
            created_at="2026-08-23T12:00:00",
        ),
        system=sys_info,
        model=ModelConfig(
            model="llama3",
            base_url="http://localhost:11434/v1",
            temperature=0.4,
            api_key_configured=False,
        ),
        metasploit=MetasploitConfig(
            host="127.0.0.1",
            port=55553,
            version="6.5.3-dev",
            password_configured=True,
        ),
        mcp=MCPConfig(
            search_url="http://localhost:8000/mcp",
            max_tool_calls=5,
        ),
        task=TaskConfig(
            input_file="evaluation_data/msf_paths.json",
            limit=None,
        ),
        output=OutputConfig(
            turn_dir="evaluation/runs/run_sample",
            blueprints_dir="blueprints",
            database_path="sqlite.db",
            log_file="run.log",
            config_file="config.json",
        ),
    )
    export_config_to_json(template_config, output_path)
    print(f"✅ Configuration template written to: {output_path}")


def main():
    parser = build_cli_parser()
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    runner = EvaluationRunner()

    if args.command == "run":
        exit_code, turn_dir, config = runner.run_evaluation(
            input_file=args.input_file,
            query=args.query,
            limit=args.limit,
            min_date=args.min_date,
            max_date=args.max_date,
            sort_date=args.sort_date,
            ai_model=args.ai_model,
            ai_base_url=args.ai_base_url,
            ai_temperature=args.ai_temperature,
            ai_api_key=args.ai_api_key,
            msf_host=args.msf_host,
            msf_port=args.msf_port,
            msf_password=args.msf_password,
            msf_version=args.msf_version,
            mcp_url=args.mcp_url,
            mcp_max_calls=args.mcp_max_calls,
            base_output_dir=args.output_dir,
            run_name=args.run_name,
            tag=args.tag,
            export_secrets=args.export_secrets,
        )
        sys.exit(exit_code)

    elif args.command == "reproduce":
        exit_code, turn_dir, config = runner.reproduce_evaluation(
            config_path=args.config,
            run_name=args.run_name,
            base_output_dir=args.output_dir,
            dry_run=args.dry_run,
            export_secrets=args.export_secrets,
        )
        sys.exit(exit_code)

    elif args.command == "list":
        handle_list(args.output_dir)

    elif args.command == "export-config":
        handle_export_config_template(args.output)


if __name__ == "__main__":
    main()
