"""
Turn lifecycle and output directory management for Vulnprint evaluations.
"""

import re
import sys
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple

if __package__ is None or __package__ == "":
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from evaluation.config_manager import load_config_from_json, EvaluationConfig
else:
    from .config_manager import load_config_from_json, EvaluationConfig


class TurnManager:
    """
    Manages evaluation turns, automatic run directory indexing, and output structure.
    """

    def __init__(self, base_dir: str = "evaluation/runs"):
        self.base_dir = Path(base_dir)

    def ensure_base_dir(self) -> Path:
        """Ensures the root runs directory exists."""
        self.base_dir.mkdir(parents=True, exist_ok=True)
        return self.base_dir

    def get_next_turn_name(self, prefix: Optional[str] = None) -> str:
        """
        Determines the next sequential run/turn name based on existing folders in base_dir.
        Example: run_001, run_002, or RUN_vulprint_1, RUN_vulprint_2.
        """
        self.ensure_base_dir()
        existing_dirs = [d.name for d in self.base_dir.iterdir() if d.is_dir()]

        if not prefix:
            # Check if directory structure resembles RUN_vulprint_X
            if "RUN" in str(self.base_dir).upper() or any(
                "RUN_vulprint_" in d for d in existing_dirs
            ):
                prefix = "RUN_vulprint_"
            else:
                prefix = "run_"

        max_num = 0
        for name in existing_dirs:
            # Match run_001 or RUN_vulprint_1
            match = re.match(rf"^{re.escape(prefix)}(\d+)", name, re.IGNORECASE)
            if match:
                try:
                    num = int(match.group(1))
                    if num > max_num:
                        max_num = num
                except ValueError:
                    pass

        next_num = max_num + 1
        if prefix.startswith("run_"):
            return f"{prefix}{next_num:03d}"
        else:
            return f"{prefix}{next_num}"

    def create_turn_directory(self, run_name: Optional[str] = None) -> Tuple[Path, str]:
        """
        Creates an isolated turn directory with the required subdirectories in order.
        Returns (turn_dir_path, resolved_run_name).
        """
        self.ensure_base_dir()
        if not run_name:
            run_name = self.get_next_turn_name()

        turn_dir = self.base_dir / run_name
        turn_dir.mkdir(parents=True, exist_ok=True)

        # Create the blueprints subdirectory
        blueprints_dir = turn_dir / "blueprints"
        blueprints_dir.mkdir(parents=True, exist_ok=True)

        return turn_dir, run_name

    def list_turns(self) -> List[Dict[str, Any]]:
        """
        Discovers and summarizes all evaluation turns in base_dir.
        """
        if not self.base_dir.exists():
            return []

        turns = []
        for child in sorted(self.base_dir.iterdir()):
            if not child.is_dir():
                continue

            turn_info: Dict[str, Any] = {
                "name": child.name,
                "path": str(child),
                "has_config": False,
                "has_db": False,
                "has_blueprints": False,
                "has_log": False,
                "blueprints_count": 0,
                "db_size_kb": 0,
                "model": "N/A",
                "status": "unknown",
                "created_at": "N/A",
                "duration_seconds": "N/A",
            }

            config_file = child / "config.json"
            db_file = child / "sqlite.db"
            blueprints_dir = child / "blueprints"
            log_file = child / "run.log"

            if config_file.is_file():
                turn_info["has_config"] = True
                try:
                    config = load_config_from_json(str(config_file))
                    turn_info["model"] = config.model.model or "N/A"
                    turn_info["status"] = config.metadata.status
                    turn_info["created_at"] = (
                        config.metadata.created_at[:19]
                        if config.metadata.created_at
                        else "N/A"
                    )
                    if config.metadata.duration_seconds is not None:
                        turn_info["duration_seconds"] = (
                            f"{config.metadata.duration_seconds:.1f}s"
                        )
                except Exception:
                    turn_info["status"] = "config_parse_error"

            if db_file.is_file():
                turn_info["has_db"] = True
                turn_info["db_size_kb"] = round(db_file.stat().st_size / 1024, 1)

            if blueprints_dir.is_dir():
                turn_info["has_blueprints"] = True
                turn_info["blueprints_count"] = len(list(blueprints_dir.glob("*.md")))

            if log_file.is_file():
                turn_info["has_log"] = True

            turns.append(turn_info)

        return turns
