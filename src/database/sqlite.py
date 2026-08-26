import sqlite3
import logging
from .base import DatabaseManager
import os


class SQLiteDatabaseManager(DatabaseManager):
    """
    Manages the SQLite database connection and schema initialization.
    """

    def __init__(self, db_path: str = "data.sqlite"):
        self.db_path = db_path
        self._logger = logging.getLogger(self.__class__.__name__)

    def get_connection(self) -> sqlite3.Connection:
        # Ensure directory exists
        db_dir = os.path.dirname(self.db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
        return sqlite3.connect(self.db_path)

    def initialize_schema(self) -> None:
        try:
            conn = self.get_connection()
            cursor = conn.cursor()

            # Enable foreign keys
            cursor.execute("PRAGMA foreign_keys = ON;")

            # msf_modules table
            cursor.execute(
                """
            CREATE TABLE IF NOT EXISTS msf_modules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT UNIQUE NOT NULL,
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

            # module_platforms table
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

            # target_systems table
            cursor.execute(
                """
            CREATE TABLE IF NOT EXISTS target_systems (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                platform TEXT NOT NULL,
                distribution TEXT DEFAULT '',
                version TEXT DEFAULT '',
                architecture TEXT DEFAULT '',
                UNIQUE (platform, distribution, version, architecture)
            );
            """
            )

            # software table
            cursor.execute(
                """
            CREATE TABLE IF NOT EXISTS software (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                cves TEXT,
                vulnerable_versions TEXT,
                required_configs TEXT,
                target_system_id INTEGER,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (path) REFERENCES msf_modules(path) ON DELETE CASCADE,
                FOREIGN KEY (target_system_id) REFERENCES target_systems(id) ON DELETE SET NULL
            );
            """
            )

            # os_guidelines table
            cursor.execute(
                """
            CREATE TABLE IF NOT EXISTS os_guidelines (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guideline TEXT NOT NULL,
                target_system_id INTEGER UNIQUE NOT NULL,
                status TEXT DEFAULT 'UNVERIFIED',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (target_system_id) REFERENCES target_systems(id) ON DELETE RESTRICT
            );
            """
            )

            # software_guidelines table
            cursor.execute(
                """
            CREATE TABLE IF NOT EXISTS software_guidelines (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guideline TEXT NOT NULL,
                software_id INTEGER NOT NULL,
                status TEXT DEFAULT 'UNVERIFIED',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (software_id) REFERENCES software(id) ON DELETE CASCADE
            );
            """
            )

            # software_guidelines_os_guidelines table (many-to-many junction table)
            cursor.execute(
                """
            CREATE TABLE IF NOT EXISTS software_guidelines_os_guidelines (
                software_guideline_id INTEGER NOT NULL,
                os_guideline_id INTEGER NOT NULL,
                PRIMARY KEY (software_guideline_id, os_guideline_id),
                FOREIGN KEY (software_guideline_id) REFERENCES software_guidelines(id) ON DELETE CASCADE,
                FOREIGN KEY (os_guideline_id) REFERENCES os_guidelines(id) ON DELETE CASCADE
            );
            """
            )

            # module_guidelines table
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

            # agent_traces table
            cursor.execute(
                """
            CREATE TABLE IF NOT EXISTS agent_traces (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                msf_path TEXT NOT NULL,
                agent_name TEXT NOT NULL,
                status TEXT NOT NULL,
                failed_step_name TEXT,
                failed_step_index INTEGER,
                error_category TEXT,
                error_message TEXT,
                diagnostic_hint TEXT,
                duration_seconds REAL,
                total_tokens INTEGER DEFAULT 0,
                prompt_tokens INTEGER DEFAULT 0,
                completion_tokens INTEGER DEFAULT 0,
                trace_json TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (msf_path) REFERENCES msf_modules(path) ON DELETE CASCADE
            );
            """
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_agent_traces_path ON agent_traces(msf_path);"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_agent_traces_status ON agent_traces(status);"
            )

            conn.commit()
            conn.close()
            self._logger.info("Database schema initialized successfully.")
        except Exception as e:
            self._logger.error(f"Error initializing SQLite database schema: {e}")
            raise
