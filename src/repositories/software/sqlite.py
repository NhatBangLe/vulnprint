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
            raise TypeError("db_manager must be an instance of DatabaseManager")
        self.db_manager: SQLiteDatabaseManager = db_manager
        self._logger = logging.getLogger(self.__class__.__name__)

    def store_software_details(self, record: SoftwareRecord) -> None:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
            INSERT OR REPLACE INTO software (path, name, cves, vulnerable_versions, required_configs)
            VALUES (?, ?, ?, ?, ?);
            """,
                (
                    record.path,
                    record.name,
                    json.dumps(record.cves),
                    json.dumps(record.vulnerable_versions),
                    json.dumps(record.required_configs),
                ),
            )
            conn.commit()
        except Exception as e:
            self._logger.error(
                f"Error storing software details for {record.path}: {e}"
            )
            raise
        finally:
            if conn:
                conn.close()

    def get_software_details(self, msf_path: str) -> Optional[SoftwareRecord]:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, path, name, cves, vulnerable_versions, required_configs FROM software WHERE path = ?;",
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
            )
        except Exception as e:
            self._logger.error(
                f"Error retrieving software details for {msf_path}: {e}"
            )
            return None
        finally:
            if conn:
                conn.close()

    def get_top_technologies(self, limit: int = 10) -> List[Tuple[str, int]]:
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
