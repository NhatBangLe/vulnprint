import sqlite3
import logging

class DatabaseManager:
    """
    Manages the SQLite database connection and schema initialization.
    """
    def __init__(self, db_path: str = "lab_hub.db"):
        self.db_path = db_path
        self._logger = logging.getLogger(self.__class__.__name__)

    def initialize_schema(self) -> None:
        """
        Initializes the entire database schema in the correct dependency order.
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Enable foreign keys
            cursor.execute("PRAGMA foreign_keys = ON;")
            
            # 1. msf_modules table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS msf_modules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT UNIQUE NOT NULL,
                name TEXT,
                display_name TEXT,
                type TEXT,
                rank TEXT,
                disclosure_date TEXT,
                platform TEXT,
                documentation TEXT,
                description TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            """)

            # 2. software_metadata table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS software_metadata (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (path) REFERENCES msf_modules(path) ON DELETE CASCADE
            );
            """)

            # 3. vulnerabilities table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT UNIQUE NOT NULL,
                cves TEXT,
                vulnerable_versions TEXT,
                required_configs TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (path) REFERENCES software_metadata(path) ON DELETE CASCADE
            );
            """)

            # 4. vm_guidelines table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS vm_guidelines (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT UNIQUE NOT NULL,
                guideline TEXT NOT NULL,
                status TEXT DEFAULT 'UNVERIFIED',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (path) REFERENCES msf_modules(path) ON DELETE CASCADE
            );
            """)

            conn.commit()
            conn.close()
            self._logger.info("Database schema initialized successfully.")
        except Exception as e:
            self._logger.error(f"Error initializing SQLite database schema: {e}")
            raise
