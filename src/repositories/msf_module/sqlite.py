from database import SQLiteDatabaseManager, DatabaseManager
import json
import logging
from typing import List, Optional, Tuple
from .base import MSFModuleRepository
from models import (
    MSFModuleRecord,
    SoftwareMetadataRecord,
    VulnerabilityRecord,
    VMGuidelineRecord,
)


class SQLiteMSFModuleRepository(MSFModuleRepository):
    """
    SQLite implementation for msf_modules table operations.
    """

    def __init__(self, db_manager: DatabaseManager):
        if not isinstance(db_manager, SQLiteDatabaseManager):
            raise TypeError("db_manager must be an instance of DatabaseManager")
        self.db_manager: SQLiteDatabaseManager = db_manager
        self._logger = logging.getLogger(self.__class__.__name__)

    def store_module_metadata(self, record: MSFModuleRecord) -> None:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
            INSERT OR REPLACE INTO msf_modules (
                path, name, display_name, type, rank, disclosure_date, platform, documentation, description
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
                (
                    record.path,
                    record.name,
                    record.display_name,
                    record.type,
                    record.rank,
                    record.disclosure_date,
                    json.dumps(record.platform),
                    record.documentation,
                    record.description,
                ),
            )
            conn.commit()
        except Exception as e:
            self._logger.error(f"Error storing module metadata for {record.path}: {e}")
            raise
        finally:
            if conn:
                conn.close()

    def get_module_metadata(self, path: str) -> Optional[MSFModuleRecord]:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT path, name, display_name, type, rank, disclosure_date, platform, documentation, description
                FROM msf_modules WHERE path = ?;
                """,
                (path,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            (
                m_path,
                m_name,
                display_name,
                m_type,
                rank,
                disclosure_date,
                platform_raw,
                doc,
                desc,
            ) = row
            return MSFModuleRecord(
                path=m_path,
                name=m_name or "",
                display_name=display_name or "",
                type=m_type or "",
                rank=rank or "",
                disclosure_date=disclosure_date or "",
                platform=json.loads(platform_raw) if platform_raw else [],
                documentation=doc or "",
                description=desc or "",
            )
        except Exception as e:
            self._logger.error(f"Error retrieving module metadata for {path}: {e}")
            return None
        finally:
            if conn:
                conn.close()

    def get_all_paths(self) -> List[str]:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT path FROM msf_modules ORDER BY path ASC;")
            return [row[0] for row in cursor.fetchall() if row[0]]
        except Exception as e:
            self._logger.error(f"Error retrieving all module paths: {e}")
            return []
        finally:
            if conn:
                conn.close()

    def get_total_count(self) -> int:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM msf_modules;")
            return int(cursor.fetchone()[0])
        except Exception as e:
            self._logger.error(f"Error getting total module count: {e}")
            return 0
        finally:
            if conn:
                conn.close()

    def get_rank_distribution(self) -> List[Tuple[str, int]]:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT rank, COUNT(*) as cnt 
                FROM msf_modules 
                WHERE rank IS NOT NULL AND rank != '' 
                GROUP BY rank 
                ORDER BY cnt DESC;
                """
            )
            return cursor.fetchall()
        except Exception as e:
            self._logger.error(f"Error getting rank distribution: {e}")
            return []
        finally:
            if conn:
                conn.close()

    def get_platform_distribution(self) -> List[Tuple[str, int]]:
        from collections import Counter

        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT platform FROM msf_modules WHERE platform IS NOT NULL;"
            )
            rows = cursor.fetchall()
            counter = Counter()
            for row in rows:
                if row[0]:
                    try:
                        plats = json.loads(row[0])
                        if isinstance(plats, list):
                            for p in plats:
                                counter[p] += 1
                        elif isinstance(plats, str):
                            counter[plats] += 1
                    except Exception:
                        pass
            return counter.most_common()
        except Exception as e:
            self._logger.error(f"Error getting platform distribution: {e}")
            return []
        finally:
            if conn:
                conn.close()

    def get_disclosure_timeline(self) -> List[Tuple[str, int]]:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT substr(disclosure_date, 1, 4) as year, COUNT(*) as cnt 
                FROM msf_modules 
                WHERE disclosure_date IS NOT NULL AND disclosure_date != '' 
                GROUP BY year 
                ORDER BY year DESC;
                """
            )
            return cursor.fetchall()
        except Exception as e:
            self._logger.error(f"Error getting disclosure timeline: {e}")
            return []
        finally:
            if conn:
                conn.close()

    def search_modules(
        self,
        software_pattern: Optional[str] = None,
        platform: Optional[str] = None,
        rank: Optional[str] = None,
    ) -> List[
        Tuple[
            MSFModuleRecord,
            Optional[SoftwareMetadataRecord],
            Optional[VulnerabilityRecord],
            Optional[VMGuidelineRecord],
        ]
    ]:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            query = """
                SELECT m.path, m.name, m.display_name, m.type, m.rank, m.disclosure_date, m.platform, m.documentation, m.description,
                       s.name as software_name,
                       v.cves, v.vulnerable_versions, v.required_configs,
                       g.guideline, g.status
                FROM msf_modules m
                LEFT JOIN software_metadata s ON m.path = s.path
                LEFT JOIN vulnerabilities v ON m.path = v.path
                LEFT JOIN vm_guidelines g ON m.path = g.path
                WHERE 1=1
            """
            params = []
            if software_pattern:
                sql_pattern = software_pattern.replace("*", "%")
                query += " AND s.name LIKE ?"
                params.append(sql_pattern)
            if platform:
                query += " AND m.platform LIKE ?"
                params.append(f"%{platform}%")
            if rank:
                query += " AND m.rank LIKE ?"
                params.append(f"%{rank}%")

            query += " ORDER BY s.name ASC, m.rank DESC"
            cursor.execute(query, tuple(params))
            rows = cursor.fetchall()

            records = []
            for row in rows:
                (
                    m_path,
                    m_name,
                    display_name,
                    mtype,
                    l_rank,
                    disclosure_date,
                    plat_raw,
                    doc,
                    desc,
                    software_name,
                    cves_raw,
                    versions_raw,
                    configs_raw,
                    guideline,
                    status,
                ) = row

                m_rec = MSFModuleRecord(
                    path=m_path,
                    name=m_name or "",
                    display_name=display_name or "",
                    type=mtype or "",
                    rank=l_rank or "",
                    disclosure_date=disclosure_date or "",
                    platform=json.loads(plat_raw) if plat_raw else [],
                    documentation=doc or "",
                    description=desc or "",
                )

                s_rec = None
                if software_name:
                    s_rec = SoftwareMetadataRecord(path=m_path, name=software_name)

                v_rec = None
                if cves_raw or versions_raw or configs_raw:
                    v_rec = VulnerabilityRecord(
                        path=m_path,
                        cves=json.loads(cves_raw) if cves_raw else [],
                        vulnerable_versions=(
                            json.loads(versions_raw) if versions_raw else []
                        ),
                        required_configs=json.loads(configs_raw) if configs_raw else [],
                    )

                g_rec = None
                if guideline:
                    g_rec = VMGuidelineRecord(
                        path=m_path,
                        guideline=guideline,
                        status=status or "UNVERIFIED",
                    )

                records.append((m_rec, s_rec, v_rec, g_rec))
            return records
        except Exception as e:
            self._logger.error(f"Error searching joined modules: {e}")
            return []
        finally:
            if conn:
                conn.close()
