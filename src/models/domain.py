from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field
from .records import (
    OSGuidelineRecord,
    SoftwareGuidelineRecord,
    MSFModuleRecord,
    SoftwareRecord,
)


class MSFModule(BaseModel):
    id: Optional[int] = Field(
        default=None, description="Unique identifier of the module"
    )
    path: str = Field(..., description="Module path")
    display_name: str = Field(..., description="Display name of the module")
    type: str = Field(..., description="Module type")
    rank: str = Field(..., description="Module rank")
    disclosure_date: str = Field(..., description="Disclosure date of the module")
    platform: List[str] = Field(
        default_factory=list, description="Platform of the module"
    )
    documentation: str = Field(default="", description="Documentation of the module")
    description: str = Field(default="", description="Description of the module")

    @classmethod
    def from_record(cls, record: MSFModuleRecord) -> "MSFModule":
        """
        Maps a MSFModuleRecord to MSFModule.
        """
        return cls(
            id=record.id,
            path=record.path,
            display_name=record.display_name,
            type=record.type,
            rank=record.rank,
            disclosure_date=record.disclosure_date,
            platform=record.platforms,
            documentation=record.documentation,
            description=record.description,
        )


class Software(BaseModel):
    id: Optional[int] = Field(
        default=None, description="Unique identifier of the software"
    )
    path: str = Field(..., description="Path of the software")
    name: str = Field(..., description="Name of the software")
    cves: List[str] = Field(default_factory=list, description="CVEs of the software")
    vulnerable_versions: List[str] = Field(
        default_factory=list,
        description="Vulnerable versions of the software",
    )
    required_configs: List[str] = Field(
        default_factory=list, description="Required configurations of the software"
    )

    @classmethod
    def from_record(
        cls,
        software_rec: SoftwareRecord,
    ) -> "Software":
        """
        Maps a SoftwareRecord to Software.
        """
        return cls(
            id=software_rec.id,
            path=software_rec.path,
            name=software_rec.name,
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
    path: str = Field(..., description="MSF module path")
    guideline: str = Field(..., description="Software guideline")
    os_guideline_id: int = Field(..., description="OS guideline ID")
    software_id: int = Field(..., description="Software ID")
    status: GuidelineStatus = Field(..., description="Guideline status")

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
