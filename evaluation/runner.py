"""
Subprocess execution runner and environment isolation for Vulnprint evaluations.
"""

import os
import sys
import time
import uuid
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple

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


if __package__ is None or __package__ == "":
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from evaluation.config_manager import (
        EvaluationConfig,
        RunMetadata,
        SystemInfo,
        ModelConfig,
        MetasploitConfig,
        MCPConfig,
        TaskConfig,
        OutputConfig,
        capture_system_info,
        calculate_file_sha256,
        count_input_modules,
        export_config_to_json,
        load_config_from_json,
    )
    from evaluation.turn_manager import TurnManager
else:
    from .config_manager import (
        EvaluationConfig,
        RunMetadata,
        SystemInfo,
        ModelConfig,
        MetasploitConfig,
        MCPConfig,
        TaskConfig,
        OutputConfig,
        capture_system_info,
        calculate_file_sha256,
        count_input_modules,
        export_config_to_json,
        load_config_from_json,
    )
    from .turn_manager import TurnManager


class EvaluationRunner:
    """
    Orchestrates an evaluation run, manages environment isolation, captures logs,
    and exports configuration JSON into the turn directory.
    """

    def __init__(self, root_dir: Optional[str] = None):
        # Locate project root (where src/ and evaluation_data/ reside)
        self.root_dir = (
            Path(root_dir) if root_dir else Path(__file__).resolve().parent.parent
        )
        self.src_main = self.root_dir / "src" / "main.py"

    def run_evaluation(
        self,
        # Task options
        input_file: Optional[str] = None,
        query: Optional[str] = None,
        limit: Optional[int] = None,
        min_date: Optional[str] = None,
        max_date: Optional[str] = None,
        sort_date: Optional[str] = None,
        # AI overrides
        ai_model: Optional[str] = None,
        ai_base_url: Optional[str] = None,
        ai_temperature: Optional[float] = None,
        ai_api_key: Optional[str] = None,
        # MSF RPC overrides
        msf_host: Optional[str] = None,
        msf_port: Optional[int] = None,
        msf_password: Optional[str] = None,
        msf_version: Optional[str] = None,
        # MCP overrides
        mcp_url: Optional[str] = None,
        mcp_max_calls: Optional[int] = None,
        # Turn / Output options
        base_output_dir: str = "evaluation/runs",
        run_name: Optional[str] = None,
        tag: Optional[str] = None,
        export_secrets: bool = False,
        reproduced_from: Optional[str] = None,
    ) -> Tuple[int, Path, EvaluationConfig]:
        """
        Executes a complete evaluation turn.
        Returns (exit_code, turn_dir_path, evaluation_config).
        """
        turn_mgr = TurnManager(base_dir=base_output_dir)
        turn_dir, resolved_run_name = turn_mgr.create_turn_directory(run_name=run_name)

        run_id = (
            f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
        )
        start_time_iso = datetime.now().isoformat()
        start_timestamp = time.time()

        # Resolve relative dataset path against root_dir if needed
        resolved_input_file = input_file
        if input_file and not os.path.isabs(input_file):
            candidate = self.root_dir / input_file
            if candidate.is_file():
                resolved_input_file = str(candidate)

        input_sha256 = (
            calculate_file_sha256(resolved_input_file) if resolved_input_file else None
        )
        input_count = (
            count_input_modules(resolved_input_file) if resolved_input_file else None
        )

        # Build isolated environment variables for child process
        proc_env = os.environ.copy()
        proc_env["PYTHONUNBUFFERED"] = "1"
        proc_env["PYTHONPATH"] = str(self.root_dir)

        # Direct Vulnprint outputs into the turn folder
        blueprints_dir_abs = str((turn_dir / "blueprints").resolve())
        database_path_abs = str((turn_dir / "sqlite.db").resolve())
        proc_env["BLUEPRINTS_DIR"] = blueprints_dir_abs
        proc_env["DATABASE_PATH"] = database_path_abs

        # Apply AI overrides if supplied
        if ai_model:
            proc_env["AI_MODEL"] = ai_model
        if ai_base_url:
            proc_env["AI_BASE_URL"] = ai_base_url
        if ai_temperature is not None:
            proc_env["AI_MODEL_TEMPERATURE"] = str(ai_temperature)
        if ai_api_key:
            proc_env["AI_API_KEY"] = ai_api_key

        # Apply MSF overrides if supplied
        if msf_host:
            proc_env["MSF_RPC_HOST"] = msf_host
        if msf_port:
            proc_env["MSF_RPC_PORT"] = str(msf_port)
        if msf_password:
            proc_env["MSF_RPC_PASSWORD"] = msf_password

        # Apply MCP overrides if supplied
        if mcp_url:
            proc_env["MCP_SEARCH_URL"] = mcp_url
        if mcp_max_calls is not None:
            proc_env["MCP_MAX_TOOL_CALLS"] = str(mcp_max_calls)

        # Build command arguments for vulnprint
        cmd = [sys.executable, str(self.src_main), "search"]

        if resolved_input_file:
            cmd.extend(["-f", resolved_input_file])
        if query:
            cmd.append(query)
        if limit and limit > 0:
            cmd.extend(["-l", str(limit)])
        if min_date:
            cmd.extend(["--min-date", min_date])
        if max_date:
            cmd.extend(["--max-date", max_date])
        if sort_date:
            cmd.extend(["--sort-date", sort_date])

        log_path = turn_dir / "run.log"
        print(f"\n{'='*70}")
        print(f"🚀 Starting Vulnprint Evaluation Turn: {resolved_run_name}")
        print(f"📁 Output Directory: {turn_dir}")
        print(f"📄 Dataset File: {resolved_input_file} ({input_count or 0} modules)")
        if ai_model:
            print(f"🤖 AI Model Override: {ai_model}")
        print(f"⚡ Command: {' '.join(cmd)}")
        print(f"{'='*70}\n")

        status = "running"
        exit_code = 1

        try:
            with open(log_path, "w", encoding="utf-8") as log_file:
                # Log header
                log_file.write(f"=== Vulnprint Evaluation Log ===\n")
                log_file.write(f"Run Name: {resolved_run_name}\n")
                log_file.write(f"Run ID: {run_id}\n")
                log_file.write(f"Started: {start_time_iso}\n")
                log_file.write(f"Command: {' '.join(cmd)}\n\n")
                log_file.flush()

                process = subprocess.Popen(
                    cmd,
                    cwd=str(self.root_dir),
                    env=proc_env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    universal_newlines=True,
                )

                if process.stdout:
                    for line in iter(process.stdout.readline, ""):
                        # Stream live to terminal stdout
                        sys.stdout.write(line)
                        sys.stdout.flush()
                        # Stream live to log file
                        log_file.write(line)
                        log_file.flush()

                process.wait()
                exit_code = process.returncode
                status = "completed" if exit_code == 0 else "failed"

        except KeyboardInterrupt:
            print("\n⚠️ Evaluation interrupted by user (Ctrl+C). Saving state...")
            status = "interrupted"
            exit_code = 130
        except Exception as e:
            print(f"\n❌ Execution error: {e}")
            status = "failed"
            exit_code = 1

        end_timestamp = time.time()
        completed_at_iso = datetime.now().isoformat()
        duration_sec = round(end_timestamp - start_timestamp, 2)

        # Detect effective values from env
        effective_ai_model = proc_env.get("AI_MODEL", ai_model)
        effective_ai_base_url = proc_env.get("AI_BASE_URL", ai_base_url)
        temp_val = proc_env.get("AI_MODEL_TEMPERATURE")
        effective_temp = float(temp_val) if temp_val is not None else ai_temperature
        has_api_key = bool(proc_env.get("AI_API_KEY") or ai_api_key)

        effective_msf_host = proc_env.get("MSF_RPC_HOST", msf_host or "127.0.0.1")
        effective_msf_port = int(proc_env.get("MSF_RPC_PORT", msf_port or 55553))
        has_msf_pass = bool(proc_env.get("MSF_RPC_PASSWORD") or msf_password)

        effective_mcp_url = proc_env.get(
            "MCP_SEARCH_URL", mcp_url or "http://localhost:8000/mcp"
        )
        max_calls_val = proc_env.get("MCP_MAX_TOOL_CALLS")
        effective_max_calls = (
            int(max_calls_val) if max_calls_val is not None else mcp_max_calls
        )

        system_info = capture_system_info(repo_dir=str(self.root_dir))

        config = EvaluationConfig(
            version="1.0.0",
            metadata=RunMetadata(
                run_id=run_id,
                run_name=resolved_run_name,
                tag=tag,
                status=status,
                created_at=start_time_iso,
                completed_at=completed_at_iso,
                duration_seconds=duration_sec,
                exit_code=exit_code,
                reproduced_from=reproduced_from,
            ),
            system=system_info,
            model=ModelConfig(
                model=effective_ai_model,
                base_url=effective_ai_base_url,
                temperature=effective_temp,
                api_key_configured=has_api_key,
                api_key_env_var="AI_API_KEY",
                api_key_raw=(proc_env.get("AI_API_KEY") if export_secrets else None),
            ),
            metasploit=MetasploitConfig(
                host=effective_msf_host,
                port=effective_msf_port,
                version=msf_version,
                password_configured=has_msf_pass,
                password_raw=(
                    proc_env.get("MSF_RPC_PASSWORD") if export_secrets else None
                ),
            ),
            mcp=MCPConfig(
                search_url=effective_mcp_url,
                max_tool_calls=effective_max_calls,
            ),
            task=TaskConfig(
                input_file=input_file,
                input_file_sha256=input_sha256,
                input_modules_count=input_count,
                query=query,
                limit=limit,
                min_date=min_date,
                max_date=max_date,
                sort_date=sort_date,
            ),
            output=OutputConfig(
                turn_dir=str(turn_dir),
                blueprints_dir="blueprints",
                database_path="sqlite.db",
                log_file="run.log",
                config_file="config.json",
            ),
        )

        config_path = turn_dir / "config.json"
        export_config_to_json(config, str(config_path))

        print(f"\n{'='*70}")
        print(
            f"🏁 Turn Finished: {resolved_run_name} (Status: {status}, Duration: {duration_sec}s)"
        )
        print(f"📦 Exported Configuration: {config_path}")
        print(f"🗄️ Database: {turn_dir / 'sqlite.db'}")
        print(f"📑 Blueprints: {turn_dir / 'blueprints'}")
        print(f"📜 Log File: {log_path}")
        print(f"{'='*70}\n")

        return exit_code, turn_dir, config

    def reproduce_evaluation(
        self,
        config_path: str,
        run_name: Optional[str] = None,
        base_output_dir: str = "evaluation/runs",
        dry_run: bool = False,
        export_secrets: bool = False,
    ) -> Tuple[int, Optional[Path], Optional[EvaluationConfig]]:
        """
        Reproduces an evaluation turn using an exported config.json file.
        """
        config = load_config_from_json(config_path)

        # Check dataset integrity
        input_file = config.task.input_file
        resolved_input_file = input_file
        if input_file and not os.path.isabs(input_file):
            candidate = self.root_dir / input_file
            if candidate.is_file():
                resolved_input_file = str(candidate)

        if resolved_input_file and os.path.isfile(resolved_input_file):
            curr_hash = calculate_file_sha256(resolved_input_file)
            if (
                config.task.input_file_sha256
                and curr_hash != config.task.input_file_sha256
            ):
                print(f"⚠️ Warning: Dataset file hash mismatch!")
                print(f"   Original SHA-256: {config.task.input_file_sha256}")
                print(f"   Current SHA-256:  {curr_hash}")
        else:
            if input_file:
                print(f"⚠️ Warning: Original input file not found: {input_file}")

        target_run_name = run_name or f"{config.metadata.run_name}_reproduced"

        if dry_run:
            print(f"\n{'='*70}")
            print(f"🔍 [DRY RUN] Reproduction Plan for: {config.metadata.run_name}")
            print(f"   Source Config: {config_path}")
            print(f"   Target Run Name: {target_run_name}")
            print(f"   Target Output Dir: {base_output_dir}")
            print(f"   Dataset: {config.task.input_file} (limit: {config.task.limit})")
            print(
                f"   AI Model: {config.model.model} (temp: {config.model.temperature})"
            )
            print(f"   MSF RPC: {config.metasploit.host}:{config.metasploit.port}")
            print(f"   MCP URL: {config.mcp.search_url}")
            print(f"{'='*70}\n")
            return 0, None, config

        return self.run_evaluation(
            input_file=config.task.input_file,
            query=config.task.query,
            limit=config.task.limit,
            min_date=config.task.min_date,
            max_date=config.task.max_date,
            sort_date=config.task.sort_date,
            ai_model=config.model.model,
            ai_base_url=config.model.base_url,
            ai_temperature=config.model.temperature,
            ai_api_key=config.model.api_key_raw,
            msf_host=config.metasploit.host,
            msf_port=config.metasploit.port,
            msf_password=config.metasploit.password_raw,
            msf_version=config.metasploit.version,
            mcp_url=config.mcp.search_url,
            mcp_max_calls=config.mcp.max_tool_calls,
            base_output_dir=base_output_dir,
            run_name=target_run_name,
            tag=f"Reproduced from {config.metadata.run_name}",
            export_secrets=export_secrets,
            reproduced_from=str(config_path),
        )
