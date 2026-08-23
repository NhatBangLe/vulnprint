"""
Configuration management and validation for Vulnprint evaluations using Pydantic.
"""

import os
import sys
import json
import hashlib
import platform
import subprocess
from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator, ConfigDict


class SystemInfo(BaseModel):
    """Host system and execution runtime metadata."""

    model_config = ConfigDict(extra="ignore")

    os_name: str = Field(..., description="Operating system name (e.g. Windows, Linux)")
    os_version: str = Field(..., description="OS release version")
    platform: str = Field(..., description="Full platform string")
    architecture: str = Field(..., description="CPU architecture")
    python_version: str = Field(..., description="Python runtime version")
    python_executable: str = Field(..., description="Path to Python interpreter")
    git_commit: Optional[str] = Field(None, description="Current Git commit hash")
    git_branch: Optional[str] = Field(None, description="Current Git branch name")
    git_dirty: Optional[bool] = Field(
        None, description="Whether git working tree had uncommitted changes"
    )


class ModelConfig(BaseModel):
    """AI / LLM endpoint and generation parameters."""

    model_config = ConfigDict(extra="ignore")

    model: Optional[str] = Field(None, description="Target AI model identifier")
    base_url: Optional[str] = Field(
        None, description="AI API base URL (e.g. Ollama, OpenRouter, OpenAI)"
    )
    temperature: Optional[float] = Field(
        None, description="Sampling temperature for the LLM", ge=0.0, le=2.0
    )
    api_key_configured: bool = Field(
        False, description="Whether an AI API key was detected/configured"
    )
    api_key_env_var: Optional[str] = Field(
        "AI_API_KEY", description="Name of the environment variable for API key"
    )
    api_key_raw: Optional[str] = Field(
        None,
        description="Raw API key (only saved if explicitly requested with --export-secrets)",
    )

    @field_validator("temperature")
    @classmethod
    def validate_temperature(cls, v: Optional[float]) -> Optional[float]:
        if v is not None and not (0.0 <= v <= 2.0):
            raise ValueError(f"Temperature must be between 0.0 and 2.0, got {v}")
        return v


class MetasploitConfig(BaseModel):
    """Metasploit RPC connection parameters."""

    model_config = ConfigDict(extra="ignore")

    host: str = Field("127.0.0.1", description="Metasploit RPC daemon host")
    port: int = Field(55553, description="Metasploit RPC daemon port", ge=1, le=65535)
    password_configured: bool = Field(
        False, description="Whether MSF RPC password was provided/configured"
    )
    password_raw: Optional[str] = Field(
        None,
        description="Raw MSF RPC password (only exported if --export-secrets is set)",
    )


class MCPConfig(BaseModel):
    """Model Context Protocol (MCP) server configuration."""

    model_config = ConfigDict(extra="ignore")

    search_url: Optional[str] = Field(
        "http://localhost:8000/mcp", description="MCP search server endpoint URL"
    )
    max_tool_calls: Optional[int] = Field(
        5, description="Maximum allowed MCP tool calls per extraction", ge=0
    )


class TaskConfig(BaseModel):
    """Evaluation task input parameters and filters."""

    model_config = ConfigDict(extra="ignore")

    input_file: Optional[str] = Field(
        None, description="Path to input dataset file containing MSF module paths"
    )
    input_file_sha256: Optional[str] = Field(
        None, description="SHA-256 checksum of the input dataset file"
    )
    input_modules_count: Optional[int] = Field(
        None, description="Number of modules in input dataset file"
    )
    query: Optional[str] = Field(
        None, description="Search query or Metasploit filter syntax"
    )
    limit: Optional[int] = Field(
        None, description="Maximum number of modules to process", ge=1
    )
    min_date: Optional[str] = Field(
        None, description="Minimum disclosure date filter (YYYY-MM-DD)"
    )
    max_date: Optional[str] = Field(
        None, description="Maximum disclosure date filter (YYYY-MM-DD)"
    )
    sort_date: Optional[str] = Field(
        None, description="Date sort order ('asc' or 'desc')"
    )

    @field_validator("sort_date")
    @classmethod
    def validate_sort_date(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v.lower() not in ["asc", "desc"]:
            raise ValueError("sort_date must be either 'asc' or 'desc'")
        return v.lower() if v else None


class OutputConfig(BaseModel):
    """Paths and organization of exported files for the turn."""

    model_config = ConfigDict(extra="ignore")

    turn_dir: str = Field(
        ..., description="Absolute or relative path to this turn's running directory"
    )
    blueprints_dir: str = Field(
        "blueprints", description="Subfolder name for generated lab blueprints"
    )
    database_path: str = Field(
        "sqlite.db", description="Filename for the SQLite database created in this turn"
    )
    log_file: str = Field(
        "run.log", description="Filename for the execution stdout/stderr log"
    )
    config_file: str = Field(
        "config.json", description="Filename for the exported configuration JSON"
    )


class RunMetadata(BaseModel):
    """Metadata tracking execution timestamps, status, and turn identification."""

    model_config = ConfigDict(extra="ignore")

    run_id: str = Field(
        ..., description="Unique run identifier (e.g. run_20260823_153000_a1b2)"
    )
    run_name: str = Field(
        ..., description="Human-readable run/turn name (e.g. run_001 or RUN_vulprint_4)"
    )
    tag: Optional[str] = Field(
        None, description="User-supplied label or description for this evaluation"
    )
    status: str = Field(
        "pending",
        description="Status of the evaluation: pending, running, completed, failed, interrupted",
    )
    created_at: str = Field(
        default_factory=lambda: datetime.now().isoformat(),
        description="ISO-8601 start timestamp",
    )
    completed_at: Optional[str] = Field(
        None, description="ISO-8601 completion timestamp"
    )
    duration_seconds: Optional[float] = Field(
        None, description="Total execution time in seconds"
    )
    exit_code: Optional[int] = Field(None, description="Process exit code")
    reproduced_from: Optional[str] = Field(
        None, description="Path or Run ID of the source run if this was reproduced"
    )


class EvaluationConfig(BaseModel):
    """Top-level evaluation configuration model encapsulating all settings."""

    model_config = ConfigDict(extra="ignore")

    version: str = Field("1.0.0", description="Configuration schema version")
    metadata: RunMetadata = Field(..., description="Run metadata and status")
    system: SystemInfo = Field(
        ..., description="Host system and Python runtime environment"
    )
    model: ModelConfig = Field(
        default_factory=ModelConfig, description="AI model configuration"
    )
    metasploit: MetasploitConfig = Field(
        default_factory=MetasploitConfig, description="Metasploit RPC configuration"
    )
    mcp: MCPConfig = Field(
        default_factory=MCPConfig, description="MCP search configuration"
    )
    task: TaskConfig = Field(
        default_factory=TaskConfig, description="Evaluation task and dataset parameters"
    )
    output: OutputConfig = Field(..., description="Output directory and file layout")


def calculate_file_sha256(file_path: str) -> Optional[str]:
    """Computes SHA-256 hash of a file if it exists."""
    if not file_path or not os.path.isfile(file_path):
        return None
    hasher = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception:
        return None


def count_input_modules(file_path: str) -> Optional[int]:
    """Counts module paths in JSON, JSONL, or line-based text file."""
    if not file_path or not os.path.isfile(file_path):
        return None
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if not content:
                return 0
            if content.startswith("[") and content.endswith("]"):
                data = json.loads(content)
                return len(data) if isinstance(data, list) else 1
            else:
                lines = [line.strip() for line in content.splitlines() if line.strip()]
                return len(lines)
    except Exception:
        return None


def get_git_info(repo_dir: Optional[str] = None) -> Dict[str, Any]:
    """Retrieves current git commit hash, branch, and status if in a git repository."""
    info: Dict[str, Any] = {"commit": None, "branch": None, "dirty": None}
    cwd = repo_dir or os.getcwd()
    try:
        commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=cwd, stderr=subprocess.DEVNULL, text=True
        ).strip()
        info["commit"] = commit
    except Exception:
        pass

    try:
        branch = subprocess.check_output(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=cwd,
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        info["branch"] = branch
    except Exception:
        pass

    try:
        status = subprocess.check_output(
            ["git", "status", "--porcelain"],
            cwd=cwd,
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        info["dirty"] = len(status) > 0
    except Exception:
        pass

    return info


def capture_system_info(repo_dir: Optional[str] = None) -> SystemInfo:
    """Captures runtime system information, Python environment, and git info."""
    git_info = get_git_info(repo_dir)
    return SystemInfo(
        os_name=platform.system(),
        os_version=platform.release(),
        platform=platform.platform(),
        architecture=platform.machine(),
        python_version=sys.version.split()[0],
        python_executable=sys.executable,
        git_commit=git_info["commit"],
        git_branch=git_info["branch"],
        git_dirty=git_info["dirty"],
    )


def export_config_to_json(config: EvaluationConfig, file_path: str) -> str:
    """Exports and saves the validated EvaluationConfig as formatted JSON."""
    os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
    json_str = config.model_dump_json(indent=2)
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(json_str)
    return file_path


def load_config_from_json(file_path: str) -> EvaluationConfig:
    """Loads and validates an EvaluationConfig from a JSON file using Pydantic."""
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Configuration file not found: {file_path}")
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()
    return EvaluationConfig.model_validate_json(content)
