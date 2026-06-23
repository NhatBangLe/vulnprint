import json
import logging
from typing import List, Optional, Tuple
from .base import SoftwareRepository
from models import SoftwareRecord
from database import DatabaseManager, SQLiteDatabaseManager


class SQLiteSoftwareRepository(SoftwareRepository):
    """
    SQLite implementation for software table operations.
    """

    def __init__(self, db_manager: DatabaseManager):
        if not isinstance(db_manager, SQLiteDatabaseManager):
            raise TypeError("db_manager must be an instance of SQLiteDatabaseManager")
        self.db_manager: SQLiteDatabaseManager = db_manager
        self._logger = logging.getLogger(self.__class__.__name__)

    def save(self, record: SoftwareRecord) -> int:
        existing_id = self.exists_by_path(record.path)
        if existing_id:
            return self._update_by_id(existing_id, record)

        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
            INSERT INTO software (path, name, cves, vulnerable_versions, required_configs, target_system_id)
            VALUES (?, ?, ?, ?, ?, ?);
            """,
                (
                    record.path,
                    record.name,
                    json.dumps(record.cves),
                    json.dumps(record.vulnerable_versions),
                    json.dumps(record.required_configs),
                    record.target_system_id,
                ),
            )
            conn.commit()
            return cursor.lastrowid
        except Exception as e:
            self._logger.error(f"Error storing software details for {record.path}: {e}")
            raise
        finally:
            if conn:
                conn.close()

    def exists_by_id(self, software_id: int) -> bool:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT 1 FROM software WHERE id = ?;",
                (software_id,),
            )
            return bool(cursor.fetchone())
        except Exception as e:
            self._logger.error(f"Error checking software existence by id: {e}")
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
                "SELECT id FROM software WHERE path = ?;",
                (msf_path,),
            )
            row = cursor.fetchone()
            return row[0] if row else None
        except Exception as e:
            self._logger.error(f"Error checking software existence by path: {e}")
            return None
        finally:
            if conn:
                conn.close()

    def get_by_id(self, software_id: int) -> Optional[SoftwareRecord]:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT s.id, s.path, s.name, s.cves, s.vulnerable_versions, s.required_configs, s.target_system_id,
                       ts.platform, ts.distribution, ts.version, ts.architecture
                FROM software s
                LEFT JOIN target_systems ts ON s.target_system_id = ts.id
                WHERE s.id = ?;
                """,
                (software_id,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            return SoftwareRecord(
                id=row[0],
                path=row[1],
                name=row[2],
                cves=json.loads(row[3]) if row[3] else [],
                vulnerable_versions=json.loads(row[4]) if row[4] else [],
                required_configs=json.loads(row[5]) if row[5] else [],
                target_system_id=row[6],
                platform=row[7] or "",
                distribution=row[8] or "",
                version=row[9] or "",
                architecture=row[10] or "",
            )
        except Exception as e:
            self._logger.error(
                f"Error retrieving software details for {software_id}: {e}"
            )
            return None
        finally:
            if conn:
                conn.close()

    def get_by_path(self, msf_path: str) -> Optional[SoftwareRecord]:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT s.id, s.path, s.name, s.cves, s.vulnerable_versions, s.required_configs, s.target_system_id,
                       ts.platform, ts.distribution, ts.version, ts.architecture
                FROM software s
                LEFT JOIN target_systems ts ON s.target_system_id = ts.id
                WHERE s.path = ?;
                """,
                (msf_path,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            return SoftwareRecord(
                id=row[0],
                path=row[1],
                name=row[2],
                cves=json.loads(row[3]) if row[3] else [],
                vulnerable_versions=json.loads(row[4]) if row[4] else [],
                required_configs=json.loads(row[5]) if row[5] else [],
                target_system_id=row[6],
                platform=row[7] or "",
                distribution=row[8] or "",
                version=row[9] or "",
                architecture=row[10] or "",
            )
        except Exception as e:
            self._logger.error(f"Error retrieving software details for {msf_path}: {e}")
            return None
        finally:
            if conn:
                conn.close()

    def get_top_software(self, limit: int = 10) -> List[Tuple[str, int]]:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT name, COUNT(*) as cnt 
                FROM software 
                WHERE name IS NOT NULL AND name != ''
                GROUP BY name 
                ORDER BY cnt DESC 
                LIMIT ?;
                """,
                (limit,),
            )
            return cursor.fetchall()
        except Exception as e:
            self._logger.error(f"Error querying top technologies: {e}")
            return []
        finally:
            if conn:
                conn.close()

    def get_all_software(self) -> List[str]:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT DISTINCT name FROM software WHERE name IS NOT NULL AND name != '' ORDER BY name ASC;"
            )
            return [row[0] for row in cursor.fetchall() if row[0]]
        except Exception as e:
            self._logger.error(f"Error retrieving unique software list: {e}")
            return []
        finally:
            if conn:
                conn.close()

    def get_required_configurations(self) -> List[str]:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT required_configs FROM software WHERE required_configs IS NOT NULL;"
            )
            rows = cursor.fetchall()
            all_configs = []
            for row in rows:
                if row[0]:
                    try:
                        configs = json.loads(row[0])
                        if isinstance(configs, list):
                            all_configs.extend(configs)
                    except Exception:
                        pass
            return all_configs
        except Exception as e:
            self._logger.error(f"Error querying configurations: {e}")
            return []
        finally:
            if conn:
                conn.close()

    def _update_by_id(self, software_id: int, record: SoftwareRecord) -> Optional[int]:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE software SET cves = ?, vulnerable_versions = ?, required_configs = ?, target_system_id = ? 
                WHERE id = ?;
                """,
                (
                    json.dumps(record.cves),
                    json.dumps(record.vulnerable_versions),
                    json.dumps(record.required_configs),
                    record.target_system_id,
                    software_id,
                ),
            )
            conn.commit()
            return software_id
        except Exception as e:
            self._logger.error(
                f"Error updating software details for {software_id}: {e}"
            )
            if conn:
                conn.rollback()
            return None
        finally:
            if conn:
                conn.close()
