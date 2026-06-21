import logging
from typing import Optional
from .base import OSGuidelineRepository
from models import OSGuidelineRecord
from database import DatabaseManager, SQLiteDatabaseManager


class SQLiteOSGuidelineRepository(OSGuidelineRepository):
    def __init__(self, db_manager: DatabaseManager):
        if not isinstance(db_manager, SQLiteDatabaseManager):
            raise TypeError("db_manager must be an instance of SQLiteDatabaseManager")
        self.db_manager: SQLiteDatabaseManager = db_manager
        self._logger = logging.getLogger(self.__class__.__name__)

    def store_os_guideline(self, record: OSGuidelineRecord) -> int:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO os_guidelines (os_name, guideline, platform, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                ON CONFLICT(os_name) DO UPDATE SET
                    guideline = excluded.guideline,
                    platform = excluded.platform,
                    updated_at = CURRENT_TIMESTAMP;
                """,
                (
                    record.os_name.lower().strip(),
                    record.guideline,
                    record.platform.lower().strip(),
                    record.status,
                ),
            )
            cursor.execute(
                "SELECT id FROM os_guidelines WHERE os_name = ?;",
                (record.os_name.lower().strip(),),
            )
            row = cursor.fetchone()
            if not row:
                raise ValueError(
                    f"Failed to retrieve stored OS guideline ID for {record.os_name}"
                )
            guideline_id = row[0]
            conn.commit()
            return guideline_id
        except Exception as e:
            self._logger.error(f"Error storing OS guideline for {record.os_name}: {e}")
            raise
        finally:
            if conn:
                conn.close()

    def get_os_guideline(self, guideline_id: int) -> Optional[OSGuidelineRecord]:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, os_name, guideline, platform, status, created_at, updated_at
                FROM os_guidelines WHERE id = ?;
                """,
                (guideline_id,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            return OSGuidelineRecord(
                id=row[0],
                os_name=row[1],
                guideline=row[2],
                platform=row[3] or "",
                status=row[4] or "UNVERIFIED",
                created_at=row[5],
                updated_at=row[6],
            )
        except Exception as e:
            self._logger.error(
                f"Error retrieving OS guideline for ID {guideline_id}: {e}"
            )
            return None
        finally:
            if conn:
                conn.close()

    def get_os_guideline_by_name(self, os_name: str) -> Optional[OSGuidelineRecord]:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, os_name, guideline, platform, status, created_at, updated_at
                FROM os_guidelines WHERE os_name = ?;
                """,
                (os_name.lower().strip(),),
            )
            row = cursor.fetchone()
            if not row:
                return None
            return OSGuidelineRecord(
                id=row[0],
                os_name=row[1],
                guideline=row[2],
                platform=row[3] or "",
                status=row[4] or "UNVERIFIED",
                created_at=row[5],
                updated_at=row[6],
            )
        except Exception as e:
            self._logger.error(f"Error retrieving OS guideline for name {os_name}: {e}")
            return None
        finally:
            if conn:
                conn.close()
