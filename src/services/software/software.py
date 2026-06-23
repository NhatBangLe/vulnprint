from typing import Tuple, List, Optional
from repositories import SoftwareRepository, TargetSystemRepository
from .base import SoftwareService
from models import Software, SoftwareRecord, TargetSystemRecord


class DefaultSoftwareService(SoftwareService):
    """
    Default implementation of the SoftwareService interface.
    """

    def __init__(
        self,
        software_repo: SoftwareRepository,
        target_system_repo: TargetSystemRepository,
    ):
        self.software_repo = software_repo
        self.target_system_repo = target_system_repo

    def store_software(self, data: Software) -> None:
        # Retrieve existing record to keep existing CVEs
        existing = self.software_repo.get_by_path(data.path)
        cves_to_store = existing.cves if existing else []

        target_system_id = None
        if data.platform:
            target_system_id = self.target_system_repo.save(
                TargetSystemRecord(
                    platform=data.platform,
                    distribution=data.distribution,
                    version=data.version,
                    architecture=data.architecture,
                )
            )

        software_rec = SoftwareRecord(
            path=data.path,
            name=data.name,
            cves=cves_to_store,
            vulnerable_versions=data.vulnerable_versions,
            required_configs=data.required_configs,
            target_system_id=target_system_id,
        )
        self.software_repo.save(software_rec)

    def get_software_by_path(self, path: str) -> Optional[Software]:
        software_rec = self.software_repo.get_by_path(path)
        if not software_rec:
            return None
        return Software.from_record(software_rec)

    def get_software_by_id(self, software_id: int) -> Optional[Software]:
        software_rec = self.software_repo.get_by_id(software_id)
        if not software_rec:
            return None
        return Software.from_record(software_rec)

    def get_top_software(self, limit: int = 10) -> List[Tuple[str, int]]:
        return self.software_repo.get_top_software(limit=limit)

    def get_all_software(self) -> List[str]:
        return self.software_repo.get_all_software()

    def get_required_configurations(self) -> List[str]:
        return self.software_repo.get_required_configurations()
