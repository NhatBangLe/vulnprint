from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field
from .records import (
    MSFModuleRecord,
    SoftwareRecord,
    OSGuidelineRecord,
    SoftwareGuidelineRecord,
)


class MetasploitModuleDetails(BaseModel):
    module_id: Optional[int] = None
    software_id: Optional[int] = None
    description: str
    cves: List[str]
    type: str = ""
    name: str = ""
    module_name: str = ""
    rank: str = ""
    disclosure_date: str = ""
    platform: List[str] = Field(default_factory=list)
    documentation: str = ""

    @classmethod
    def from_record(
        cls, msf_rec: MSFModuleRecord, software_rec: Optional[SoftwareRecord] = None
    ) -> "MetasploitModuleDetails":
        """
        Maps an MSFModuleRecord and optional SoftwareRecord to MetasploitModuleDetails.
        """
        return cls(
            module_id=msf_rec.id,
            software_id=software_rec.id if software_rec else None,
            description=msf_rec.description,
            cves=software_rec.cves if software_rec else [],
            type=msf_rec.type,
            name=msf_rec.display_name,
            module_name=msf_rec.name,
            rank=msf_rec.rank,
            disclosure_date=msf_rec.disclosure_date,
            platform=msf_rec.platform,
            documentation=msf_rec.documentation,
        )


class VulnerabilityTarget(BaseModel):
    id: Optional[int] = None
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

    @classmethod
    def from_record(
        cls,
        software_rec: SoftwareRecord,
    ) -> "VulnerabilityTarget":
        """
        Maps a SoftwareRecord to VulnerabilityTarget.
        """
        return cls(
            id=software_rec.id,
            software_name=software_rec.name,
            vulnerable_versions=software_rec.vulnerable_versions,
            required_configs=software_rec.required_configs,
        )


class GuidelineStatus(Enum):
    UNVERIFIED = "UNVERIFIED"
    REJECTED = "REJECTED"
    VERIFIED = "VERIFIED"


class OSGuideline(BaseModel):
    id: Optional[int] = None
    os_name: str
    guideline: str
    status: GuidelineStatus = GuidelineStatus.UNVERIFIED
    platform: str = ""

    @classmethod
    def from_record(cls, record: OSGuidelineRecord) -> "OSGuideline":
        """
        Maps an OSGuidelineRecord to OSGuideline.
        """
        real_status: GuidelineStatus
        match record.status:
            case GuidelineStatus.UNVERIFIED.value:
                real_status = GuidelineStatus.UNVERIFIED
            case GuidelineStatus.REJECTED.value:
                real_status = GuidelineStatus.REJECTED
            case GuidelineStatus.VERIFIED.value:
                real_status = GuidelineStatus.VERIFIED
            case _:
                raise ValueError(f"Invalid status: {record.status}")

        return cls(
            id=record.id,
            os_name=record.os_name,
            guideline=record.guideline,
            status=real_status,
            platform=record.platform,
        )


class SoftwareGuideline(BaseModel):
    id: Optional[int] = None
    path: str = ""
    guideline: str
    os_guideline_id: int
    software_id: int
    status: GuidelineStatus = GuidelineStatus.UNVERIFIED

    @classmethod
    def from_record(cls, record: SoftwareGuidelineRecord) -> "SoftwareGuideline":
        """
        Maps a SoftwareGuidelineRecord to SoftwareGuideline.
        """
        real_status: GuidelineStatus
        match record.status:
            case GuidelineStatus.UNVERIFIED.value:
                real_status = GuidelineStatus.UNVERIFIED
            case GuidelineStatus.REJECTED.value:
                real_status = GuidelineStatus.REJECTED
            case GuidelineStatus.VERIFIED.value:
                real_status = GuidelineStatus.VERIFIED
            case _:
                raise ValueError(f"Invalid status: {record.status}")

        return cls(
            id=record.id,
            path=record.path,
            guideline=record.guideline,
            os_guideline_id=record.os_guideline_id,
            software_id=record.software_id,
            status=real_status,
        )


class VMGuidelineMetadata(BaseModel):
    guideline_id: int
    guideline_text: str
    status: str
    platform: str
    associated_software_name: str
    associated_platforms: List[str] = Field(default_factory=list)
    associated_versions: List[str] = Field(default_factory=list)
    module_paths: List[str] = Field(default_factory=list)


class GuidelineCoverageItem(BaseModel):
    guideline_id: int
    software_name: str
    status: str
    modules_covered: List[str] = Field(default_factory=list)
    coverage_count: int


class VMGuidelineCoverageStats(BaseModel):
    total_guidelines: int
    average_coverage: float
    guidelines: List[GuidelineCoverageItem] = Field(default_factory=list)
