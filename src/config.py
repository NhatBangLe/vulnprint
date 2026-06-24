import os
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

# Dynamically locate the .env file in the repository root directory
# (which is the parent of the 'src' directory)
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_FILE_PATH = os.path.join(ROOT_DIR, ".env")


class Settings(BaseSettings):
    msf_rpc_host: str = Field("127.0.0.1", validation_alias="MSF_RPC_HOST")
    msf_rpc_port: int = Field(55553, validation_alias="MSF_RPC_PORT")
    msf_rpc_password: Optional[str] = Field(None, validation_alias="MSF_RPC_PASSWORD")

    ai_base_url: str = Field(
        "https://openrouter.ai/api/v1", validation_alias="AI_BASE_URL"
    )
    ai_model: str = Field(validation_alias="AI_MODEL")
    ai_api_key: Optional[str] = Field(None, validation_alias="AI_API_KEY")

    blueprints_dir: str = Field(
        "vulnprint_blueprints", validation_alias="BLUEPRINTS_DIR"
    )
    database_path: str = Field("data.sqlite", validation_alias="DATABASE_PATH")
    log_level: str = Field("INFO", validation_alias="LOG_LEVEL")

    mcp_search_url: str = Field(
        "http://localhost:8000/mcp", validation_alias="MCP_SEARCH_URL"
    )
    mcp_max_tool_calls: int = Field(5, validation_alias="MCP_MAX_TOOL_CALLS")

    model_config = SettingsConfigDict(
        env_file=ENV_FILE_PATH, env_file_encoding="utf-8", extra="ignore"
    )


# Instantiate the global settings object
settings = Settings()
