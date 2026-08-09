from typing import List, Tuple, Optional
from repositories import MSFModuleRepository, SoftwareRepository
from models import (
    MetasploitModuleDetails,
    MSFModuleRecord,
    MSFModule,
    Software,
)
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

    def store_module(self, data: MetasploitModuleDetails | MSFModule) -> Optional[int]:
        if isinstance(data, MetasploitModuleDetails):
            module_rec = MSFModuleRecord(
                path=data.module_name,
                display_name=data.name,
                type=data.type,
                rank=data.rank,
                disclosure_date=data.disclosure_date,
                platforms=data.platform,
                documentation=data.documentation,
                description=data.description,
            )
        else:
            module_rec = MSFModuleRecord(
                path=data.path,
                display_name=data.display_name,
                type=data.type,
                rank=data.rank,
                disclosure_date=data.disclosure_date,
                platforms=data.platform,
                documentation=data.documentation,
                description=data.description,
            )
        return self.msf_repo.save(module_rec)

    def get_module_by_id(self, module_id: int) -> Optional[MSFModule]:
        msf_rec = self.msf_repo.get_by_id(module_id)
        if not msf_rec:
            return None
        return MSFModule.from_record(msf_rec)

    def get_module_by_path(self, path: str) -> Optional[MSFModule]:
        msf_rec = self.msf_repo.get_by_path(path)
        if not msf_rec:
            return None
        return MSFModule.from_record(msf_rec)

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
        min_date: Optional[str] = None,
        max_date: Optional[str] = None,
        msf_path: Optional[str] = None,
    ) -> List[Tuple[MSFModule, Optional[Software]]]:
        joined_records = self.msf_repo.search_modules(
            software_pattern=software_pattern,
            platform=platform,
            rank=rank,
            min_date=min_date,
            max_date=max_date,
            msf_path=msf_path,
        )
        results = []
        for m_rec, s_rec in joined_records:
            results.append(
                (
                    MSFModule.from_record(m_rec),
                    Software.from_record(s_rec) if s_rec else None,
                )
            )
        return results
