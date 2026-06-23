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
        existing_guideline_id = self.exists_by_target_system(record.target_system_id)
        if existing_guideline_id:
            return self._update_by_id(existing_guideline_id, record)

        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO os_guidelines (guideline, target_system_id, status, created_at, updated_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                """,
                (
                    record.guideline,
                    record.target_system_id,
                    record.status,
                ),
            )
            guideline_id = cursor.lastrowid
            conn.commit()
            return guideline_id
        except Exception as e:
            self._logger.error(
                f"Error storing OS guideline for target system ID {record.target_system_id}: {e}"
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

    def exists_by_target_system(self, target_system_id: int) -> Optional[int]:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id FROM os_guidelines WHERE target_system_id = ?;",
                (target_system_id,),
            )
            row = cursor.fetchone()
            return row[0] if row else None
        except Exception as e:
            self._logger.error(
                f"Error checking if OS guideline exists for target system ID {target_system_id}: {e}"
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
                SELECT og.id, og.guideline, og.target_system_id, og.status,
                       ts.platform, ts.distribution, ts.version, ts.architecture,
                       og.created_at, og.updated_at
                FROM os_guidelines og
                JOIN target_systems ts ON og.target_system_id = ts.id
                WHERE og.id = ?;
                """,
                (guideline_id,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            return OSGuidelineRecord(
                id=row[0],
                guideline=row[1],
                target_system_id=row[2],
                status=row[3] or "UNVERIFIED",
                platform=row[4] or "",
                distribution=row[5] or "",
                version=row[6] or "",
                architecture=row[7] or "",
                created_at=row[8],
                updated_at=row[9],
            )
        except Exception as e:
            self._logger.error(
                f"Error retrieving OS guideline for ID {guideline_id}: {e}"
            )
            return None
        finally:
            if conn:
                conn.close()

    def get_all_guidelines(self) -> list[OSGuidelineRecord]:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT og.id, og.guideline, og.target_system_id, og.status,
                       ts.platform, ts.distribution, ts.version, ts.architecture,
                       og.created_at, og.updated_at
                FROM os_guidelines og
                JOIN target_systems ts ON og.target_system_id = ts.id;
                """
            )
            rows = cursor.fetchall()
            results = []
            for row in rows:
                results.append(
                    OSGuidelineRecord(
                        id=row[0],
                        guideline=row[1],
                        target_system_id=row[2],
                        status=row[3] or "UNVERIFIED",
                        platform=row[4] or "",
                        distribution=row[5] or "",
                        version=row[6] or "",
                        architecture=row[7] or "",
                        created_at=row[8],
                        updated_at=row[9],
                    )
                )
            return results
        except Exception as e:
            self._logger.error(f"Error retrieving all OS guidelines: {e}")
            return []
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
                UPDATE os_guidelines SET guideline = ?, target_system_id = ?, status = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?;
                """,
                (
                    record.guideline,
                    record.target_system_id,
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
