import sqlite3
import logging
from .base import DatabaseManager


class SQLiteDatabaseManager(DatabaseManager):
    """
    Manages the SQLite database connection and schema initialization.
    """

    def __init__(self, db_path: str = "lab_hub.db"):
        self.db_path = db_path
        self._logger = logging.getLogger(self.__class__.__name__)

    def get_connection(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def initialize_schema(self) -> None:
        try:
            conn = self.get_connection()
            cursor = conn.cursor()

            # Enable foreign keys
            cursor.execute("PRAGMA foreign_keys = ON;")

            # 1. msf_modules table
            cursor.execute(
                """
            CREATE TABLE IF NOT EXISTS msf_modules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT UNIQUE NOT NULL,
                name TEXT,
                display_name TEXT,
                type TEXT,
                rank TEXT,
                disclosure_date TEXT,
                documentation TEXT,
                description TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            """
            )

            # 2. module_platforms table
            cursor.execute(
                """
            CREATE TABLE IF NOT EXISTS module_platforms (
                module_path TEXT NOT NULL,
                platform TEXT NOT NULL,
                PRIMARY KEY (module_path, platform),
                FOREIGN KEY (module_path) REFERENCES msf_modules(path) ON DELETE CASCADE
            );
            """
            )

            # 2. software table
            cursor.execute(
                """
            CREATE TABLE IF NOT EXISTS software (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                cves TEXT,
                vulnerable_versions TEXT,
                required_configs TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (path) REFERENCES msf_modules(path) ON DELETE CASCADE
            );
            """
            )

            # 3. os_guidelines table
            cursor.execute(
                """
            CREATE TABLE IF NOT EXISTS os_guidelines (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                os_name TEXT UNIQUE NOT NULL,
                guideline TEXT NOT NULL,
                platform TEXT,
                status TEXT DEFAULT 'UNVERIFIED',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            """
            )

            # 4. software_guidelines table
            cursor.execute(
                """
            CREATE TABLE IF NOT EXISTS software_guidelines (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guideline TEXT NOT NULL,
                os_guideline_id INTEGER NOT NULL,
                software_id INTEGER NOT NULL,
                status TEXT DEFAULT 'UNVERIFIED',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (os_guideline_id) REFERENCES os_guidelines(id) ON DELETE CASCADE,
                FOREIGN KEY (software_id) REFERENCES software(id) ON DELETE CASCADE
            );
            """
            )

            # 5. module_guidelines table
            cursor.execute(
                """
            CREATE TABLE IF NOT EXISTS module_guidelines (
                module_path TEXT NOT NULL,
                guideline_id INTEGER NOT NULL,
                PRIMARY KEY (module_path, guideline_id),
                FOREIGN KEY (module_path) REFERENCES msf_modules(path) ON DELETE CASCADE,
                FOREIGN KEY (guideline_id) REFERENCES software_guidelines(id) ON DELETE CASCADE
            );
            """
            )

            conn.commit()
            conn.close()
            self._logger.info("Database schema initialized successfully.")
        except Exception as e:
            self._logger.error(f"Error initializing SQLite database schema: {e}")
            raise
