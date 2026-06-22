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

    def save(self, record: OSGuidelineRecord) -> Optional[int]:
        existing_guideline_id = self.exists_by_name(record.os_name)
        if existing_guideline_id:
            return self._update_by_id(existing_guideline_id, record)

        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO os_guidelines (os_name, guideline, platform, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
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
                "SELECT 1 FROM os_guidelines WHERE id = ?;",
                (guideline_id,),
            )
            return bool(cursor.fetchone())
        except Exception as e:
            self._logger.error(
                f"Error checking if OS guideline exists for ID {guideline_id}: {e}"
            )
            return False
        finally:
            if conn:
                conn.close()

    def exists_by_name(self, os_name: str) -> Optional[int]:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id FROM os_guidelines WHERE os_name = ?;",
                (os_name.lower().strip(),),
            )
            row = cursor.fetchone()
            return row[0] if row else None
        except Exception as e:
            self._logger.error(
                f"Error checking if OS guideline exists for name {os_name}: {e}"
            )
            return None
        finally:
            if conn:
                conn.close()

    def get_by_id(self, guideline_id: int) -> Optional[OSGuidelineRecord]:
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

    def get_by_name(self, os_name: str) -> Optional[OSGuidelineRecord]:
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

    def _update_by_id(
        self, guideline_id: int, record: OSGuidelineRecord
    ) -> Optional[int]:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE os_guidelines SET guideline = ?, platform = ?, status = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?;
                """,
                (
                    record.guideline,
                    record.platform.lower().strip(),
                    record.status,
                    guideline_id,
                ),
            )
            conn.commit()
            return guideline_id
        except Exception as e:
            self._logger.error(
                f"Error updating OS guideline for ID {guideline_id}: {e}"
            )
            if conn:
                conn.rollback()
            return None
        finally:
            if conn:
                conn.close()
