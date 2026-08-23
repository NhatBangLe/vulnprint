from typing import List, Optional
from pydantic import BaseModel, Field


class MSFModuleRecord(BaseModel):
    id: Optional[int] = None
    path: str
    display_name: str = ""
    type: str = ""
    rank: str = ""
    disclosure_date: str = ""
    platforms: List[str] = Field(default_factory=list)
    documentation: str = ""
    description: str = ""


class TargetSystemRecord(BaseModel):
    id: Optional[int] = None
    platform: str
    distribution: str = ""
    version: str = ""
    architecture: str = ""


class SoftwareRecord(BaseModel):
    id: Optional[int] = None
    path: str
    name: str = ""
    cves: List[str] = Field(default_factory=list)
    vulnerable_versions: List[str] = Field(default_factory=list)
    required_configs: List[str] = Field(default_factory=list)
    target_system_id: Optional[int] = None
    platform: str = ""
    distribution: str = ""
    version: str = ""
    architecture: str = ""


class OSGuidelineRecord(BaseModel):
    id: Optional[int] = None
    guideline: str
    target_system_id: Optional[int] = None
    platform: str = ""
    distribution: str = ""
    version: str = ""
    architecture: str = ""
    status: str = "UNVERIFIED"
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class SoftwareGuidelineRecord(BaseModel):
    id: Optional[int] = None
    path: str = ""
    guideline: str
    os_guideline_ids: List[int] = Field(default_factory=list)
    software_id: int
    status: str = "UNVERIFIED"
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class AgentTraceRecord(BaseModel):
    id: Optional[int] = None
    msf_path: str
    agent_name: str
    status: str = "SUCCESS"  # 'SUCCESS' or 'FAILED'
    failed_step_name: Optional[str] = None
    failed_step_index: Optional[int] = None
    error_category: Optional[str] = None
    error_message: Optional[str] = None
    diagnostic_hint: Optional[str] = None
    duration_seconds: Optional[float] = None
    trace_json: Optional[str] = None
    created_at: Optional[str] = None
