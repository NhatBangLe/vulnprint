import logging
from typing import List, Optional, Tuple
from .base import SoftwareMetadataRepository
from models import SoftwareMetadataRecord
from database import DatabaseManager, SQLiteDatabaseManager


class SQLiteSoftwareMetadataRepository(SoftwareMetadataRepository):
    """
    SQLite implementation for software_metadata table operations.
    """

    def __init__(self, db_manager: DatabaseManager):
        if not isinstance(db_manager, SQLiteDatabaseManager):
            raise TypeError("db_manager must be an instance of DatabaseManager")
        self.db_manager: SQLiteDatabaseManager = db_manager
        self._logger = logging.getLogger(self.__class__.__name__)

    def store_software_metadata(self, record: SoftwareMetadataRecord) -> None:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
            INSERT OR REPLACE INTO software_metadata (path, name) VALUES (?, ?);
            """,
                (record.path, record.name),
            )
            conn.commit()
        except Exception as e:
            self._logger.error(
                f"Error storing software metadata for {record.path}: {e}"
            )
            raise
        finally:
            if conn:
                conn.close()

    def get_software_metadata(self, msf_path: str) -> Optional[SoftwareMetadataRecord]:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT path, name FROM software_metadata WHERE path = ?;", (msf_path,)
            )
            row = cursor.fetchone()
            if not row:
                return None
            return SoftwareMetadataRecord(path=row[0], name=row[1])
        except Exception as e:
            self._logger.error(
                f"Error retrieving software metadata for {msf_path}: {e}"
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
                FROM software_metadata 
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
                "SELECT DISTINCT name FROM software_metadata WHERE name IS NOT NULL ORDER BY name ASC;"
            )
            return [row[0] for row in cursor.fetchall() if row[0]]
        except Exception as e:
            self._logger.error(f"Error retrieving unique software list: {e}")
            return []
        finally:
            if conn:
                conn.close()
