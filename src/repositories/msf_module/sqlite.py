from database import SQLiteDatabaseManager, DatabaseManager
import json
import logging
from typing import List, Optional, Tuple
from .base import MSFModuleRepository
from models import (
    MSFModuleRecord,
    SoftwareRecord,
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
                INSERT INTO msf_modules (
                    path, name, display_name, type, rank, disclosure_date, documentation, description
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(path) DO UPDATE SET
                    name = excluded.name,
                    display_name = excluded.display_name,
                    type = excluded.type,
                    rank = excluded.rank,
                    disclosure_date = excluded.disclosure_date,
                    documentation = excluded.documentation,
                    description = excluded.description;
                """,
                (
                    record.path,
                    record.name,
                    record.display_name,
                    record.type,
                    record.rank,
                    record.disclosure_date,
                    record.documentation,
                    record.description,
                ),
            )
            for plat in record.platform:
                cursor.execute(
                    """
                    INSERT OR IGNORE INTO module_platforms (module_path, platform)
                    VALUES (?, ?);
                    """,
                    (record.path, plat),
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
                SELECT id, path, name, display_name, type, rank, disclosure_date, documentation, description
                FROM msf_modules WHERE path = ?;
                """,
                (path,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            (
                m_id,
                m_path,
                m_name,
                display_name,
                m_type,
                rank,
                disclosure_date,
                doc,
                desc,
            ) = row

            cursor.execute(
                """
                SELECT platform FROM module_platforms WHERE module_path = ?;
                """,
                (path,),
            )
            platforms = [r[0] for r in cursor.fetchall() if r[0]]

            return MSFModuleRecord(
                id=m_id,
                path=m_path,
                name=m_name or "",
                display_name=display_name or "",
                type=m_type or "",
                rank=rank or "",
                disclosure_date=disclosure_date or "",
                platform=platforms,
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
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT platform, COUNT(*) as cnt
                FROM module_platforms
                GROUP BY platform
                ORDER BY cnt DESC;
                """
            )
            return cursor.fetchall()
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
            Optional[SoftwareRecord],
            Optional[VMGuidelineRecord],
        ]
    ]:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            query = """
                SELECT m.id, m.path, m.name, m.display_name, m.type, m.rank, m.disclosure_date,
                       (SELECT group_concat(platform) FROM module_platforms WHERE module_path = m.path) as platforms,
                       m.documentation, m.description,
                       s.id as software_id, s.name as software_name, s.cves, s.vulnerable_versions, s.required_configs,
                       g.id as guideline_id, g.guideline, g.status, g.platform as guideline_platform
                FROM msf_modules m
                LEFT JOIN software s ON m.path = s.path
                LEFT JOIN module_guidelines mg ON m.path = mg.module_path
                LEFT JOIN vm_guidelines g ON mg.guideline_id = g.id
                WHERE 1=1
            """
            params = []
            if software_pattern:
                sql_pattern = software_pattern.replace("*", "%")
                query += " AND s.name LIKE ?"
                params.append(sql_pattern)
            if platform:
                query += " AND EXISTS (SELECT 1 FROM module_platforms WHERE module_path = m.path AND platform LIKE ?)"
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
                    m_id,
                    m_path,
                    m_name,
                    display_name,
                    mtype,
                    l_rank,
                    disclosure_date,
                    plat_raw,
                    doc,
                    desc,
                    software_id,
                    software_name,
                    cves_raw,
                    versions_raw,
                    configs_raw,
                    guideline_id,
                    guideline,
                    status,
                    guideline_platform,
                ) = row

                m_rec = MSFModuleRecord(
                    id=m_id,
                    path=m_path,
                    name=m_name or "",
                    display_name=display_name or "",
                    type=mtype or "",
                    rank=l_rank or "",
                    disclosure_date=disclosure_date or "",
                    platform=plat_raw.split(",") if plat_raw else [],
                    documentation=doc or "",
                    description=desc or "",
                )

                s_rec = None
                if software_name or cves_raw or versions_raw or configs_raw:
                    s_rec = SoftwareRecord(
                        id=software_id,
                        path=m_path,
                        name=software_name or "",
                        cves=json.loads(cves_raw) if cves_raw else [],
                        vulnerable_versions=(
                            json.loads(versions_raw) if versions_raw else []
                        ),
                        required_configs=json.loads(configs_raw) if configs_raw else [],
                    )

                g_rec = None
                if guideline:
                    g_rec = VMGuidelineRecord(
                        id=guideline_id,
                        path=m_path,
                        guideline=guideline,
                        status=status or "UNVERIFIED",
                        platform=guideline_platform or "",
                    )

                records.append((m_rec, s_rec, g_rec))
            return records
        except Exception as e:
            self._logger.error(f"Error searching joined modules: {e}")
            return []
        finally:
            if conn:
                conn.close()
