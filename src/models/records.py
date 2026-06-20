from typing import List, Optional
from pydantic import BaseModel, Field


class MSFModuleRecord(BaseModel):
    id: Optional[int] = None
    path: str
    name: str
    display_name: str = ""
    type: str = ""
    rank: str = ""
    disclosure_date: str = ""
    platform: List[str] = Field(default_factory=list)
    documentation: str = ""
    description: str = ""


class SoftwareRecord(BaseModel):
    id: Optional[int] = None
    path: str
    name: str = ""
    cves: List[str] = Field(default_factory=list)
    vulnerable_versions: List[str] = Field(default_factory=list)
    required_configs: List[str] = Field(default_factory=list)


class VMGuidelineRecord(BaseModel):
    id: Optional[int] = None
    path: str
    guideline: str
    status: str = "UNVERIFIED"
    platform: str = ""
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
