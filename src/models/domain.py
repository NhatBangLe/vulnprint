from enum import Enum
from typing import List, Optional, Tuple
from pydantic import BaseModel, Field, model_validator
from .records import (
    OSGuidelineRecord,
    SoftwareGuidelineRecord,
    MSFModuleRecord,
    SoftwareRecord,
)


def parse_os_name(os_name: str, platform: str) -> Tuple[str, str, str]:
    name = os_name.lower().strip()
    plat = platform.lower().strip()

    # 1. Extract architecture
    architecture = "64-bit"  # default
    if "32" in name:
        architecture = "32-bit"
    elif "64" in name:
        architecture = "64-bit"

    # Remove architecture part from the name to make version/distribution parsing easier
    for term in ["(32-bit)", "(64-bit)", "32-bit", "64-bit", "(32)", "(64)"]:
        name = name.replace(term, "")
    name = name.strip()

    distribution = ""
    version = ""

    if plat == "windows":
        distribution = "windows"
        name_clean = name.replace("windows", "").strip()
        if "server" in name_clean:
            distribution = "windows server"
            name_clean = name_clean.replace("server", "").strip()
            version = name_clean
        else:
            words = name_clean.split()
            if words:
                distribution = f"windows {words[0]}"
                version = " ".join(words[1:])
    else:
        words = name.split()
        if words:
            dist_candidate = words[0]
            if dist_candidate in [
                "ubuntu",
                "debian",
                "centos",
                "redhat",
                "fedora",
                "suse",
                "alpine",
                "mint",
            ]:
                distribution = dist_candidate
                version = " ".join(words[1:])
            else:
                distribution = dist_candidate
                version = " ".join(words[1:])
        else:
            distribution = plat

    return distribution.strip(), version.strip(), architecture.strip()


class MSFModule(BaseModel):
    id: Optional[int] = Field(
        default=None, description="Unique identifier of the module"
    )
    path: str = Field(..., description="Module path")
    display_name: str = Field(..., description="Display name of the module")
    type: str = Field(..., description="Module type")
    rank: str = Field(..., description="Module rank")
    disclosure_date: str = Field(..., description="Disclosure date of the module")
    platforms: List[str] = Field(
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
    target_system_id: Optional[int] = None
    platform: str = ""
    distribution: str = ""
    version: str = ""
    architecture: str = ""

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
            target_system_id=software_rec.target_system_id,
            platform=software_rec.platform,
            distribution=software_rec.distribution,
            version=software_rec.version,
            architecture=software_rec.architecture,
        )


class GuidelineStatus(Enum):
    UNVERIFIED = "UNVERIFIED"
    REJECTED = "REJECTED"
    VERIFIED = "VERIFIED"


class TargetSystem(BaseModel):
    id: Optional[int] = None
    platform: str
    distribution: str = ""
    version: str = ""
    architecture: str = ""


class OSGuideline(BaseModel):
    id: Optional[int] = None
    guideline: str
    status: GuidelineStatus = GuidelineStatus.UNVERIFIED
    target_system_id: Optional[int] = None
    platform: str = ""
    distribution: str = ""
    version: str = ""
    architecture: str = ""

    @property
    def os_name(self) -> str:
        parts = []
        if self.distribution:
            parts.append(self.distribution)
        else:
            parts.append(self.platform)
        if self.version:
            parts.append(self.version)
        if self.architecture:
            parts.append(f"({self.architecture})")
        return " ".join(parts)

    @model_validator(mode="after")
    def populate_target_system_components(self) -> "OSGuideline":
        if self.os_name and self.platform and not self.distribution:
            dist, ver, arch = parse_os_name(self.os_name, self.platform)
            self.distribution = dist
            self.version = ver
            self.architecture = arch
        return self

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

        # Dynamically reconstruct os_name from platform components
        parts = []
        if record.distribution:
            parts.append(record.distribution)
        else:
            parts.append(record.platform)
        if record.version:
            parts.append(record.version)
        if record.architecture:
            parts.append(f"({record.architecture})")
        os_name = " ".join(parts)

        return cls(
            id=record.id,
            os_name=os_name,
            guideline=record.guideline,
            status=real_status,
            target_system_id=record.target_system_id,
            platform=record.platform,
            distribution=record.distribution,
            version=record.version,
            architecture=record.architecture,
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


class SoftwareGuidelineMetadata(BaseModel):
    guideline_id: int
    guideline_text: str
    status: str
    platform: str
    associated_software_name: str
    associated_platforms: List[str] = Field(default_factory=list)
    associated_versions: List[str] = Field(default_factory=list)
    module_paths: List[str] = Field(default_factory=list)


class SoftwareGuidelineCoverageItem(BaseModel):
    guideline_id: int
    software_name: str
    status: str
    modules_covered: List[str] = Field(default_factory=list)
    coverage_count: int


class SoftwareGuidelineCoverageStats(BaseModel):
    total_guidelines: int
    average_coverage: float
    guidelines: List[SoftwareGuidelineCoverageItem] = Field(default_factory=list)


class OSGuidelineCoverageItem(BaseModel):
    guideline_id: int
    os_name: str
    status: str
    coverage_count: int


class OSGuidelineCoverageStats(BaseModel):
    total_os_guidelines: int
    average_coverage: float
    guidelines: List[OSGuidelineCoverageItem] = Field(default_factory=list)
