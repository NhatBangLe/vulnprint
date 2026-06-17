from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field
from .records import (
    MSFModuleRecord,
    SoftwareMetadataRecord,
    VulnerabilityRecord,
    VMGuidelineRecord,
)


class MetasploitModuleDetails(BaseModel):
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
        cls, msf_rec: MSFModuleRecord, vuln_rec: Optional[VulnerabilityRecord] = None
    ) -> "MetasploitModuleDetails":
        """
        Maps an MSFModuleRecord and optional VulnerabilityRecord to MetasploitModuleDetails.
        """
        return cls(
            description=msf_rec.description,
            cves=vuln_rec.cves if vuln_rec else [],
            type=msf_rec.type,
            name=msf_rec.display_name,
            module_name=msf_rec.name,
            rank=msf_rec.rank,
            disclosure_date=msf_rec.disclosure_date,
            platform=msf_rec.platform,
            documentation=msf_rec.documentation,
        )


class VulnerabilityTarget(BaseModel):
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
    def from_records(
        cls,
        software_rec: SoftwareMetadataRecord,
        vuln_rec: Optional[VulnerabilityRecord] = None,
    ) -> "VulnerabilityTarget":
        """
        Maps a SoftwareMetadataRecord and optional VulnerabilityRecord to VulnerabilityTarget.
        """
        return cls(
            software_name=software_rec.name,
            vulnerable_versions=vuln_rec.vulnerable_versions if vuln_rec else [],
            required_configs=vuln_rec.required_configs if vuln_rec else [],
        )


class VMGuidelineStatus(Enum):
    UNVERIFIED = "UNVERIFIED"
    REJECTED = "REJECTED"
    VERIFIED = "VERIFIED"


class VMGuideline(BaseModel):
    path: str
    guideline: str
    status: VMGuidelineStatus = VMGuidelineStatus.UNVERIFIED

    @classmethod
    def from_record(cls, record: VMGuidelineRecord) -> "VMGuideline":
        """
        Maps a VMGuidelineRecord to VMGuideline.
        """
        real_status: VMGuidelineStatus
        match record.status:
            case VMGuidelineStatus.UNVERIFIED.value:
                real_status = VMGuidelineStatus.UNVERIFIED
            case VMGuidelineStatus.REJECTED.value:
                real_status = VMGuidelineStatus.REJECTED
            case VMGuidelineStatus.VERIFIED.value:
                real_status = VMGuidelineStatus.VERIFIED
            case _:
                raise ValueError(f"Invalid status: {record.status}")

        return cls(
            path=record.path,
            guideline=record.guideline,
            status=real_status,
        )
