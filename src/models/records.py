from typing import List, Optional
from pydantic import BaseModel, Field


class MSFModuleRecord(BaseModel):
    path: str
    name: str
    display_name: str = ""
    type: str = ""
    rank: str = ""
    disclosure_date: str = ""
    platform: List[str] = Field(default_factory=list)
    documentation: str = ""
    description: str = ""


class SoftwareMetadataRecord(BaseModel):
    path: str
    name: str


class VulnerabilityRecord(BaseModel):
    path: str
    cves: List[str] = Field(default_factory=list)
    vulnerable_versions: List[str] = Field(default_factory=list)
    required_configs: List[str] = Field(default_factory=list)


class VMGuidelineRecord(BaseModel):
    path: str
    guideline: str
    status: str = "UNVERIFIED"
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
