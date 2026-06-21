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


class OSGuidelineRecord(BaseModel):
    id: Optional[int] = None
    os_name: str
    guideline: str
    platform: str = ""
    status: str = "UNVERIFIED"
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class SoftwareGuidelineRecord(BaseModel):
    id: Optional[int] = None
    path: str = ""
    guideline: str
    os_guideline_id: int
    software_id: int
    status: str = "UNVERIFIED"
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
