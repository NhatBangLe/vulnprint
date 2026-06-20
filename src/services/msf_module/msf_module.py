from typing import List, Tuple, Optional
from repositories import MSFModuleRepository, SoftwareRepository
from models import MetasploitModuleDetails, MSFModuleRecord, SoftwareRecord
from .base import MSFModuleService


class DefaultMSFModuleService(MSFModuleService):
    """
    Default implementation of the MSFModuleService interface.
    """

    def __init__(
        self, msf_repo: MSFModuleRepository, software_repo: SoftwareRepository
    ):
        self.msf_repo = msf_repo
        self.software_repo = software_repo

    def store_module_details(self, details: MetasploitModuleDetails) -> None:
        record = MSFModuleRecord(
            path=details.module_name,
            name=details.module_name,
            display_name=details.name,
            type=details.type,
            rank=details.rank,
            disclosure_date=details.disclosure_date,
            platform=details.platform,
            documentation=details.documentation,
            description=details.description,
        )
        self.msf_repo.store_module_metadata(record)

        # Retrieve existing software record to keep name, versions & configs
        existing = self.software_repo.get_software_details(details.module_name)
        software_name = existing.name if existing else ""
        versions = existing.vulnerable_versions if existing else []
        configs = existing.required_configs if existing else []

        software_rec = SoftwareRecord(
            path=details.module_name,
            name=software_name,
            cves=details.cves,
            vulnerable_versions=versions,
            required_configs=configs,
        )
        self.software_repo.store_software_details(software_rec)

    def get_module_details(self, path: str) -> Optional[MetasploitModuleDetails]:
        msf_rec = self.msf_repo.get_module_metadata(path)
        if not msf_rec:
            return None
        software_rec = self.software_repo.get_software_details(path)
        return MetasploitModuleDetails.from_record(msf_rec, software_rec)

    def get_all_paths(self) -> List[str]:
        return self.msf_repo.get_all_paths()

    def get_total_count(self) -> int:
        return self.msf_repo.get_total_count()

    def get_rank_distribution(self) -> List[Tuple[str, int]]:
        return self.msf_repo.get_rank_distribution()

    def get_platform_distribution(self) -> List[Tuple[str, int]]:
        return self.msf_repo.get_platform_distribution()

    def get_disclosure_timeline(self) -> List[Tuple[str, int]]:
        return self.msf_repo.get_disclosure_timeline()

    def search_modules(
        self,
        software_pattern: Optional[str] = None,
        platform: Optional[str] = None,
        rank: Optional[str] = None,
    ) -> List[MetasploitModuleDetails]:
        joined_records = self.msf_repo.search_modules(
            software_pattern=software_pattern, platform=platform, rank=rank
        )
        results = []
        for m_rec, s_rec, g_rec in joined_records:
            results.append(MetasploitModuleDetails.from_record(m_rec, s_rec))
        return results
