import json
import logging
from typing import List, Optional
from .base import VMGuidelineRepository
from models import VMGuidelineRecord, VMGuidelineMetadata
from database import DatabaseManager, SQLiteDatabaseManager


class SQLiteVMGuidelineRepository(VMGuidelineRepository):
    def __init__(self, db_manager: DatabaseManager):
        if not isinstance(db_manager, SQLiteDatabaseManager):
            raise TypeError("db_manager must be an instance of DatabaseManager")
        self.db_manager: SQLiteDatabaseManager = db_manager
        self._logger = logging.getLogger(self.__class__.__name__)

    def store_vm_guideline(self, record: VMGuidelineRecord) -> None:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT INTO vm_guidelines (guideline, status, platform, created_at, updated_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
                """,
                (record.guideline, record.status, record.platform),
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
        except Exception as e:
            self._logger.error(f"Error storing VM guideline for {record.path}: {e}")
            raise
        finally:
            if conn:
                conn.close()

    def get_vm_guideline(self, guideline_id: int) -> Optional[VMGuidelineRecord]:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT g.id, mg.module_path, g.guideline, g.status, g.platform, g.created_at, g.updated_at
                FROM vm_guidelines g
                LEFT JOIN module_guidelines mg ON g.id = mg.guideline_id
                WHERE g.id = ?;
                """,
                (guideline_id,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            return VMGuidelineRecord(
                id=row[0],
                path=row[1] or "",
                guideline=row[2],
                status=row[3],
                platform=row[4] or "",
                created_at=row[5],
                updated_at=row[6],
            )
        except Exception as e:
            self._logger.error(
                f"Error retrieving VM guideline for ID {guideline_id}: {e}"
            )
            return None
        finally:
            if conn:
                conn.close()

    def get_vm_guideline_by_path(self, msf_path: str) -> List[VMGuidelineRecord]:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT g.id, mg.module_path, g.guideline, g.status, g.platform, g.created_at, g.updated_at
                FROM vm_guidelines g
                JOIN module_guidelines mg ON g.id = mg.guideline_id
                WHERE mg.module_path = ?
                ORDER BY g.created_at DESC;
                """,
                (msf_path,),
            )
            rows = cursor.fetchall()
            results = []
            for row in rows:
                results.append(
                    VMGuidelineRecord(
                        id=row[0],
                        path=row[1],
                        guideline=row[2],
                        status=row[3],
                        platform=row[4] or "",
                        created_at=row[5],
                        updated_at=row[6],
                    )
                )
            return results
        except Exception as e:
            self._logger.error(f"Error retrieving VM guidelines for {msf_path}: {e}")
            return []
        finally:
            if conn:
                conn.close()

    def get_unverified_guidelines(self) -> List[VMGuidelineRecord]:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT g.id, mg.module_path, g.guideline, g.status, g.platform, g.created_at, g.updated_at
                FROM vm_guidelines g
                JOIN module_guidelines mg ON g.id = mg.guideline_id
                WHERE g.status = 'UNVERIFIED'
                ORDER BY g.created_at ASC;
                """
            )
            rows = cursor.fetchall()
            results = []
            for row in rows:
                results.append(
                    VMGuidelineRecord(
                        id=row[0],
                        path=row[1],
                        guideline=row[2],
                        status=row[3],
                        platform=row[4] or "",
                        created_at=row[5],
                        updated_at=row[6],
                    )
                )
            return results
        except Exception as e:
            self._logger.error(f"Error querying unverified guidelines: {e}")
            return []
        finally:
            if conn:
                conn.close()

    def update_guideline_status(
        self, msf_path: str, status: str, guideline: Optional[str] = None
    ) -> None:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()

            # Find the latest guideline_id associated with this path
            cursor.execute(
                "SELECT guideline_id FROM module_guidelines WHERE module_path = ? ORDER BY guideline_id DESC LIMIT 1;",
                (msf_path,),
            )
            row = cursor.fetchone()
            if row:
                guideline_id = row[0]
                if guideline is not None:
                    cursor.execute(
                        """
                        UPDATE vm_guidelines 
                        SET status = ?, guideline = ?, updated_at = CURRENT_TIMESTAMP 
                        WHERE id = ?;
                        """,
                        (status, guideline, guideline_id),
                    )
                else:
                    cursor.execute(
                        """
                        UPDATE vm_guidelines 
                        SET status = ?, updated_at = CURRENT_TIMESTAMP 
                        WHERE id = ?;
                        """,
                        (status, guideline_id),
                    )
                conn.commit()
            else:
                self._logger.warning(
                    f"No guideline found to update for path: {msf_path}"
                )
        except Exception as e:
            self._logger.error(f"Error updating guideline status for {msf_path}: {e}")
            raise
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
                SELECT g.id, g.guideline, g.status, g.platform, mg.module_path, s.name, s.vulnerable_versions
                FROM vm_guidelines g
                LEFT JOIN module_guidelines mg ON g.id = mg.guideline_id
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
                        associated_software_name=data["associated_software_name"],
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
