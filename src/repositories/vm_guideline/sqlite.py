import sqlite3
import logging
from typing import List, Optional
from .base import VMGuidelineRepository
from models import VMGuidelineRecord


class SQLiteVMGuidelineRepository(VMGuidelineRepository):
    """
    SQLite implementation for vm_guidelines table operations.
    """

    def __init__(self, db_path: str = "lab_hub.db"):
        self.db_path = db_path
        self._logger = logging.getLogger(self.__class__.__name__)

    def store_vm_guideline(self, record: VMGuidelineRecord) -> None:
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO vm_guidelines (path, guideline, status, created_at, updated_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                ON CONFLICT(path) DO UPDATE SET
                    guideline = excluded.guideline,
                    status = excluded.status,
                    updated_at = CURRENT_TIMESTAMP;
                """,
                (record.path, record.guideline, record.status),
            )
            conn.commit()
        except Exception as e:
            self._logger.error(f"Error storing VM guideline for {record.path}: {e}")
            raise
        finally:
            if conn:
                conn.close()

    def get_vm_guideline(self, path: str) -> Optional[VMGuidelineRecord]:
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT path, guideline, status, created_at, updated_at FROM vm_guidelines WHERE path = ?;",
                (path,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            return VMGuidelineRecord(
                path=row[0],
                guideline=row[1],
                status=row[2],
                created_at=row[3],
                updated_at=row[4],
            )
        except Exception as e:
            self._logger.error(f"Error retrieving VM guideline for {path}: {e}")
            return None
        finally:
            if conn:
                conn.close()

    def get_unverified_guidelines(self) -> List[VMGuidelineRecord]:
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT path, guideline, status, created_at, updated_at
                FROM vm_guidelines
                WHERE status = 'UNVERIFIED'
                ORDER BY created_at ASC;
                """
            )
            rows = cursor.fetchall()
            results = []
            for row in rows:
                results.append(
                    VMGuidelineRecord(
                        path=row[0],
                        guideline=row[1],
                        status=row[2],
                        created_at=row[3],
                        updated_at=row[4],
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
        self, path: str, status: str, guideline: Optional[str] = None
    ) -> None:
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            if guideline is not None:
                cursor.execute(
                    """
                    UPDATE vm_guidelines 
                    SET status = ?, guideline = ?, updated_at = CURRENT_TIMESTAMP 
                    WHERE path = ?;
                    """,
                    (status, guideline, path),
                )
            else:
                cursor.execute(
                    """
                    UPDATE vm_guidelines 
                    SET status = ?, updated_at = CURRENT_TIMESTAMP 
                    WHERE path = ?;
                    """,
                    (status, path),
                )
            conn.commit()
        except Exception as e:
            self._logger.error(f"Error updating guideline status for {path}: {e}")
            raise
        finally:
            if conn:
                conn.close()
