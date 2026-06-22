from models import MSFModuleRecord, SoftwareRecord
from typing import List, Optional
from pydantic import BaseModel, Field


class MetasploitModuleDetails(BaseModel):
    name: str = ""
    description: str
    cves: List[str]
    type: str = ""
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
