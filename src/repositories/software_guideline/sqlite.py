import logging
from typing import List, Optional
from .base import SoftwareGuidelineRepository
from models import SoftwareGuidelineRecord, VMGuidelineMetadata
from database import DatabaseManager, SQLiteDatabaseManager


class SQLiteSoftwareGuidelineRepository(SoftwareGuidelineRepository):
    def __init__(self, db_manager: DatabaseManager):
        if not isinstance(db_manager, SQLiteDatabaseManager):
            raise TypeError("db_manager must be an instance of SQLiteDatabaseManager")
        self.db_manager: SQLiteDatabaseManager = db_manager
        self._logger = logging.getLogger(self.__class__.__name__)

    def save(self, record: SoftwareGuidelineRecord) -> Optional[int]:
        existing_id = self.exists_by_path(record.path)
        if existing_id:
            return self._update_by_id(existing_id, record)

        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO software_guidelines (guideline, os_guideline_id, software_id, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
                """,
                (
                    record.guideline,
                    record.os_guideline_id,
                    record.software_id,
                    record.status,
                ),
            )
            guideline_id = cursor.lastrowid
            cursor.execute(
                """
                INSERT INTO module_guidelines (module_path, guideline_id)
                VALUES (?, ?);
                """,
                (record.path, guideline_id),
            )
            conn.commit()
            return guideline_id
        except Exception as e:
            self._logger.error(
                f"Error storing software guideline for {record.path}: {e}"
            )
            return None
        finally:
            if conn:
                conn.close()

    def exists_by_id(self, guideline_id: int) -> bool:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT 1 FROM software_guidelines WHERE id = ? LIMIT 1;",
                (guideline_id,),
            )
            return cursor.fetchone() is not None
        except Exception as e:
            self._logger.error(
                f"Error checking existence of guideline {guideline_id}: {e}"
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
                "SELECT guideline_id FROM module_guidelines WHERE module_path = ? LIMIT 1;",
                (msf_path,),
            )
            row = cursor.fetchone()
            return row[0] if row else None
        except Exception as e:
            self._logger.error(
                f"Error checking existence of guideline for path {msf_path}: {e}"
            )
            return None
        finally:
            if conn:
                conn.close()

    def get_by_id(self, guideline_id: int) -> Optional[SoftwareGuidelineRecord]:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT sg.id, sg.guideline, sg.os_guideline_id, sg.software_id, sg.status, mg.module_path, sg.created_at, sg.updated_at
                FROM software_guidelines sg
                LEFT JOIN module_guidelines mg ON sg.id = mg.guideline_id
                WHERE sg.id = ?;
                """,
                (guideline_id,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            return SoftwareGuidelineRecord(
                id=row[0],
                guideline=row[1],
                os_guideline_id=row[2],
                software_id=row[3],
                status=row[4] or "UNVERIFIED",
                path=row[5] or "",
                created_at=row[6],
                updated_at=row[7],
            )
        except Exception as e:
            self._logger.error(
                f"Error retrieving software guideline for ID {guideline_id}: {e}"
            )
            return None
        finally:
            if conn:
                conn.close()

    def get_by_path(self, msf_path: str) -> List[SoftwareGuidelineRecord]:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT sg.id, sg.guideline, sg.os_guideline_id, sg.software_id, sg.status, mg.module_path, sg.created_at, sg.updated_at
                FROM software_guidelines sg
                JOIN module_guidelines mg ON sg.id = mg.guideline_id
                WHERE mg.module_path = ?
                ORDER BY sg.created_at DESC;
                """,
                (msf_path,),
            )
            rows = cursor.fetchall()
            results = []
            for row in rows:
                results.append(
                    SoftwareGuidelineRecord(
                        id=row[0],
                        guideline=row[1],
                        os_guideline_id=row[2],
                        software_id=row[3],
                        status=row[4] or "UNVERIFIED",
                        path=row[5] or "",
                        created_at=row[6],
                        updated_at=row[7],
                    )
                )
            return results
        except Exception as e:
            self._logger.error(
                f"Error retrieving software guidelines for {msf_path}: {e}"
            )
            return []
        finally:
            if conn:
                conn.close()

    def get_unverified_guidelines(self) -> List[SoftwareGuidelineRecord]:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT sg.id, sg.guideline, sg.os_guideline_id, sg.software_id, sg.status, mg.module_path, sg.created_at, sg.updated_at
                FROM software_guidelines sg
                LEFT JOIN module_guidelines mg ON sg.id = mg.guideline_id
                WHERE sg.status = 'UNVERIFIED'
                ORDER BY sg.created_at ASC;
                """
            )
            rows = cursor.fetchall()
            results = []
            for row in rows:
                results.append(
                    SoftwareGuidelineRecord(
                        id=row[0],
                        guideline=row[1],
                        os_guideline_id=row[2],
                        software_id=row[3],
                        status=row[4] or "UNVERIFIED",
                        path=row[5] or "",
                        created_at=row[6],
                        updated_at=row[7],
                    )
                )
            return results
        except Exception as e:
            self._logger.error(f"Error querying unverified guidelines: {e}")
            return []
        finally:
            if conn:
                conn.close()

    def link_guideline_to_module(self, msf_path: str, guideline_id: int) -> None:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR IGNORE INTO module_guidelines (module_path, guideline_id)
                VALUES (?, ?);
                """,
                (msf_path, guideline_id),
            )
            conn.commit()
            self._logger.info(
                f"Linked existing guideline ID {guideline_id} to module {msf_path}"
            )
        except Exception as e:
            self._logger.error(
                f"Error linking guideline ID {guideline_id} to module {msf_path}: {e}"
            )
            raise
        finally:
            if conn:
                conn.close()

    def get_guidelines_with_software_metadata(self) -> List[VMGuidelineMetadata]:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()

            # Get all platform mapping rows
            cursor.execute("SELECT module_path, platform FROM module_platforms;")
            platform_rows = cursor.fetchall()
            module_to_platforms = {}
            for path, plat in platform_rows:
                if path and plat:
                    module_to_platforms.setdefault(path, []).append(plat)

            # Get all guidelines, their linked modules, and software targets
            cursor.execute(
                """
                SELECT sg.id, sg.guideline, sg.status, og.platform, mg.module_path, s.name, s.vulnerable_versions
                FROM software_guidelines sg
                LEFT JOIN os_guidelines og ON sg.os_guideline_id = og.id
                LEFT JOIN module_guidelines mg ON sg.id = mg.guideline_id
                LEFT JOIN software s ON mg.module_path = s.path;
                """
            )
            rows = cursor.fetchall()

            guidelines_dict = {}
            for row in rows:
                (
                    g_id,
                    guideline_text,
                    status,
                    g_plat,
                    module_path,
                    s_name,
                    s_vers_raw,
                ) = row

                if g_id not in guidelines_dict:
                    guidelines_dict[g_id] = {
                        "guideline_id": g_id,
                        "guideline_text": guideline_text,
                        "status": status,
                        "platform": g_plat or "",
                        "associated_software_name": s_name or "",
                        "associated_platforms": set(),
                        "associated_versions": set(),
                        "module_paths": [],
                    }

                g_entry = guidelines_dict[g_id]
                if s_name and not g_entry["associated_software_name"]:
                    g_entry["associated_software_name"] = s_name

                if module_path:
                    if module_path not in g_entry["module_paths"]:
                        g_entry["module_paths"].append(module_path)
                    if module_path in module_to_platforms:
                        g_entry["associated_platforms"].update(
                            module_to_platforms[module_path]
                        )
                    if s_vers_raw:
                        try:
                            import json

                            versions = json.loads(s_vers_raw)
                            if isinstance(versions, list):
                                g_entry["associated_versions"].update(versions)
                        except Exception:
                            pass

            result = []
            for g_id, data in guidelines_dict.items():
                result.append(
                    VMGuidelineMetadata(
                        guideline_id=data["guideline_id"],
                        guideline_text=data["guideline_text"],
                        status=data["status"],
                        platform=data["platform"],
                        associated_software_name=data["associated_software_name"]
                        or "Unknown Software",
                        associated_platforms=sorted(list(data["associated_platforms"])),
                        associated_versions=sorted(list(data["associated_versions"])),
                        module_paths=data["module_paths"],
                    )
                )
            return result
        except Exception as e:
            self._logger.error(
                f"Error retrieving guidelines with software metadata: {e}"
            )
            return []
        finally:
            if conn:
                conn.close()

    def _update_by_id(
        self, guideline_id: int, record: SoftwareGuidelineRecord
    ) -> Optional[int]:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE software_guidelines
                SET guideline = ?, os_guideline_id = ?, software_id = ?, status = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?;
                """,
                (
                    record.guideline,
                    record.os_guideline_id,
                    record.software_id,
                    record.status,
                    guideline_id,
                ),
            )
            if cursor.rowcount == 0:
                return None
            conn.commit()
            return guideline_id
        except Exception as e:
            self._logger.error(
                f"Error updating software guideline for ID {guideline_id}: {e}"
            )
            if conn:
                conn.rollback()
            return None
        finally:
            if conn:
                conn.close()
