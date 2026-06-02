from typing import List, Optional
from pydantic import BaseModel, Field


class CLIArguments(BaseModel):
    search: Optional[str] = None
    analytics: bool = False
    summary: bool = False


class ExploitDetails(BaseModel):
    software_name: str = Field(
        ..., description="Normalized generic name of the application"
    )
    vulnerable_versions: List[str] = Field(
        default_factory=list,
        description="Explicit version number array, e.g., ['9.0.30']",
    )
    required_configs: List[str] = Field(
        default_factory=list,
        description="Explicit application environment flags, e.g., ['AJP connector enabled']",
    )


class MetasploitModuleDetails(BaseModel):
    description: str
    cves: List[str]


class VulnerabilityRecord(BaseModel):
    msf_path: str
    cves: List[str]
    software_name: str
    vulnerable_versions: List[str]
    required_configs: List[str]
    raw_description: str
