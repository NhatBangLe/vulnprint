from database import SQLiteDatabaseManager, DatabaseManager
import json
import logging
from typing import List, Optional, Tuple
from .base import MSFModuleRepository
from models import (
    MSFModuleRecord,
    SoftwareRecord,
    OSGuidelineRecord,
    SoftwareGuidelineRecord,
)


class SQLiteMSFModuleRepository(MSFModuleRepository):
    """
    SQLite implementation for msf_modules table operations.
    """

    def __init__(self, db_manager: DatabaseManager):
        if not isinstance(db_manager, SQLiteDatabaseManager):
            raise TypeError("db_manager must be an instance of SQLiteDatabaseManager")
        self.db_manager: SQLiteDatabaseManager = db_manager
        self._logger = logging.getLogger(self.__class__.__name__)

    def save(self, record: MSFModuleRecord) -> Optional[int]:
        existing_record_id = self.exists_by_path(record.path)
        if existing_record_id:
            return self._update_by_id(existing_record_id, record)

        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO msf_modules (
                    path, display_name, type, rank, disclosure_date, documentation, description
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.path,
                    record.display_name,
                    record.type,
                    record.rank,
                    record.disclosure_date,
                    record.documentation,
                    record.description,
                ),
            )
            module_id = cursor.lastrowid
            for plat in record.platform:
                cursor.execute(
                    """
                    INSERT OR IGNORE INTO module_platforms (module_path, platform)
                    VALUES (?, ?);
                    """,
                    (record.path, plat.lower().strip()),
                )
            conn.commit()
            return module_id
        except Exception as e:
            self._logger.error(f"Error storing module metadata for {record.path}: {e}")
            return None
        finally:
            if conn:
                conn.close()

    def exists_by_id(self, module_id: int) -> bool:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT 1 FROM msf_modules WHERE id = ?;",
                (module_id,),
            )
            return bool(cursor.fetchone())
        except Exception as e:
            self._logger.error(
                f"Error checking module existence by id for {module_id}: {e}"
            )
            return False
        finally:
            if conn:
                conn.close()

    def exists_by_path(self, msf_path: str) -> Optional[int]:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id FROM msf_modules WHERE path = ?;",
                (msf_path,),
            )
            row = cursor.fetchone()
            return row[0] if row else None
        except Exception as e:
            self._logger.error(
                f"Error checking module existence by path for {msf_path}: {e}"
            )
            return None
        finally:
            if conn:
                conn.close()

    def get_by_id(self, module_id: int) -> Optional[MSFModuleRecord]:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, path, display_name, type, rank, disclosure_date, documentation, description
                FROM msf_modules WHERE id = ?;
                """,
                (module_id,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            (
                m_id,
                m_path,
                display_name,
                m_type,
                rank,
                disclosure_date,
                doc,
                desc,
            ) = row

            platforms = self._get_module_platforms(m_path, cursor)
            return MSFModuleRecord(
                id=m_id,
                path=m_path,
                display_name=display_name or "",
                type=m_type or "",
                rank=rank or "",
                disclosure_date=disclosure_date or "",
                platform=platforms,
                documentation=doc or "",
                description=desc or "",
            )
        except Exception as e:
            self._logger.error(f"Error retrieving module metadata for {module_id}: {e}")
            return None
        finally:
            if conn:
                conn.close()

    def get_by_path(self, msf_path: str) -> Optional[MSFModuleRecord]:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, path, display_name, type, rank, disclosure_date, documentation, description
                FROM msf_modules WHERE path = ?;
                """,
                (msf_path,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            (
                m_id,
                m_path,
                display_name,
                m_type,
                rank,
                disclosure_date,
                doc,
                desc,
            ) = row

            platforms = self._get_module_platforms(m_path, cursor)
            return MSFModuleRecord(
                id=m_id,
                path=m_path,
                display_name=display_name or "",
                type=m_type or "",
                rank=rank or "",
                disclosure_date=disclosure_date or "",
                platforms=platforms,
                documentation=doc or "",
                description=desc or "",
            )
        except Exception as e:
            self._logger.error(f"Error retrieving module metadata for {msf_path}: {e}")
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
            Optional[SoftwareGuidelineRecord],
            Optional[OSGuidelineRecord],
        ]
    ]:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            query = """
                SELECT m.id, m.path, m.display_name, m.type, m.rank, m.disclosure_date,
                       (SELECT group_concat(platform) FROM module_platforms WHERE module_path = m.path) as platforms,
                       m.documentation, m.description,
                       s.id as software_id, s.name as software_name, s.cves, s.vulnerable_versions, s.required_configs,
                       sg.id as guideline_id, sg.guideline as software_guideline, sg.status, og.platform as guideline_platform,
                       og.id as os_guideline_id, og.os_name, og.guideline as os_guideline
                FROM msf_modules m
                LEFT JOIN software s ON m.path = s.path
                LEFT JOIN module_guidelines mg ON m.path = mg.module_path
                LEFT JOIN software_guidelines sg ON mg.guideline_id = sg.id
                LEFT JOIN os_guidelines og ON sg.os_guideline_id = og.id
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
                    software_guideline,
                    status,
                    guideline_platform,
                    os_guideline_id,
                    os_name,
                    os_guideline,
                ) = row

                m_rec = MSFModuleRecord(
                    id=m_id,
                    path=m_path,
                    display_name=display_name or "",
                    type=mtype or "",
                    rank=l_rank or "",
                    disclosure_date=disclosure_date or "",
                    platforms=plat_raw.split(",") if plat_raw else [],
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

                sg_rec = None
                og_rec = None
                if guideline_id:
                    sg_rec = SoftwareGuidelineRecord(
                        id=guideline_id,
                        guideline=software_guideline or "",
                        os_guideline_id=os_guideline_id,
                        software_id=software_id,
                        status=status or "UNVERIFIED",
                    )
                    og_rec = OSGuidelineRecord(
                        id=os_guideline_id,
                        os_name=os_name or "",
                        guideline=os_guideline or "",
                        platform=guideline_platform or "",
                        status="VERIFIED",
                    )

                records.append((m_rec, s_rec, sg_rec, og_rec))
            return records
        except Exception as e:
            self._logger.error(f"Error searching joined modules: {e}")
            return []
        finally:
            if conn:
                conn.close()

    def _get_module_platforms(self, module_path: str, cursor) -> List[str]:
        cursor.execute(
            """
            SELECT platform FROM module_platforms WHERE module_path = ?;
            """,
            (module_path,),
        )
        platforms = [r[0] for r in cursor.fetchall() if r[0]]
        return platforms

    def _update_by_id(self, module_id: int, record: MSFModuleRecord) -> Optional[int]:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE msf_modules
                SET display_name = ?, type = ?, rank = ?, disclosure_date = ?, documentation = ?, description = ?
                WHERE id = ?;
                """,
                (
                    record.display_name,
                    record.type,
                    record.rank,
                    record.disclosure_date,
                    record.documentation,
                    record.description,
                    module_id,
                ),
            )
            conn.commit()
            return module_id
        except Exception as e:
            self._logger.error(f"Error updating module by id {module_id}: {e}")
            if conn:
                conn.rollback()
            return None
        finally:
            if conn:
                conn.close()
