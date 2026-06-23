import logging
from typing import Optional
from .base import TargetSystemRepository
from models import TargetSystemRecord
from database import DatabaseManager, SQLiteDatabaseManager


class SQLiteTargetSystemRepository(TargetSystemRepository):
    def __init__(self, db_manager: DatabaseManager):
        if not isinstance(db_manager, SQLiteDatabaseManager):
            raise TypeError("db_manager must be an instance of SQLiteDatabaseManager")
        self.db_manager: SQLiteDatabaseManager = db_manager
        self._logger = logging.getLogger(self.__class__.__name__)

    def exists(self, record: TargetSystemRecord) -> Optional[int]:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id FROM target_systems 
                WHERE platform = ? AND distribution = ? AND version = ? AND architecture = ?;
                """,
                (
                    record.platform.lower().strip(),
                    record.distribution.lower().strip(),
                    record.version.lower().strip(),
                    record.architecture.lower().strip(),
                ),
            )
            row = cursor.fetchone()
            return row[0] if row else None
        except Exception as e:
            self._logger.error(f"Error checking if target system exists: {e}")
            return None
        finally:
            if conn:
                conn.close()

    def save(self, record: TargetSystemRecord) -> Optional[int]:
        existing_id = self.exists(record)
        if existing_id is not None:
            return self._update_by_id(existing_id, record)

        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO target_systems (platform, distribution, version, architecture)
                VALUES (?, ?, ?, ?);
                """,
                (
                    record.platform.lower().strip(),
                    record.distribution.lower().strip(),
                    record.version.lower().strip(),
                    record.architecture.lower().strip(),
                ),
            )
            target_id = cursor.lastrowid
            conn.commit()
            return target_id
        except Exception as e:
            self._logger.error(f"Error storing target system record: {e}")
            return None
        finally:
            if conn:
                conn.close()

    def get_by_id(self, target_system_id: int) -> Optional[TargetSystemRecord]:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, platform, distribution, version, architecture
                FROM target_systems WHERE id = ?;
                """,
                (target_system_id,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            return TargetSystemRecord(
                id=row[0],
                platform=row[1] or "",
                distribution=row[2] or "",
                version=row[3] or "",
                architecture=row[4] or "",
            )
        except Exception as e:
            self._logger.error(
                f"Error retrieving target system record for ID {target_system_id}: {e}"
            )
            return None
        finally:
            if conn:
                conn.close()

    def _update_by_id(
        self, target_system_id: int, record: TargetSystemRecord
    ) -> Optional[int]:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE target_systems 
                SET platform = ?, distribution = ?, version = ?, architecture = ?
                WHERE id = ?;
                """,
                (
                    record.platform.lower().strip(),
                    record.distribution.lower().strip(),
                    record.version.lower().strip(),
                    record.architecture.lower().strip(),
                    target_system_id,
                ),
            )
            conn.commit()
            return target_system_id
        except Exception as e:
            self._logger.error(f"Error updating target system record: {e}")
            if conn:
                conn.rollback()
            return None
        finally:
            if conn:
                conn.close()
