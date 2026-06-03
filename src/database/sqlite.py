import sqlite3
import json
import logging
from typing import List, Optional, Tuple

try:
    from src.database.base import VulnerabilityRepository
    from src.models import ExploitDetails, VulnerabilityRecord, MetasploitModuleDetails
except ImportError:
    from .base import VulnerabilityRepository
    from models import ExploitDetails, VulnerabilityRecord, MetasploitModuleDetails


class SQLiteVulnerabilityRepository(VulnerabilityRepository):
    """
    Concrete implementation of VulnerabilityRepository using SQLite.
    """

    def __init__(self, db_path: str = "lab_hub.db"):
        self.db_path = db_path
        self._logger = logging.getLogger(self.__class__.__name__)

    def initialize(self) -> None:
        """
        Establishes connection to the SQLite database and initializes the
        vulnerabilities table if it does not already exist.
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Create vulnerabilities table
            cursor.execute(
                """
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                msf_path TEXT UNIQUE NOT NULL,
                cves TEXT,                  -- Stored as a JSON-formatted array string
                software_name TEXT NOT NULL,
                vulnerable_versions TEXT,   -- Stored as a JSON-formatted array string
                required_configs TEXT,      -- Stored as a JSON-formatted array string
                raw_description TEXT,
                type TEXT,
                name TEXT,
                module_name TEXT,
                rank TEXT,
                disclosure_date TEXT,
                platform TEXT,              -- Stored as a JSON-formatted array string
                documentation TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            """
            )
            conn.commit()
            conn.close()
        except Exception as e:
            self._logger.error(f"Error initializing SQLite repository database: {e}")
            raise

    def store_vulnerability(
        self,
        data: ExploitDetails,
        details: MetasploitModuleDetails,
    ) -> None:
        """
        Serializes Python arrays and performs an INSERT OR REPLACE to upsert target profiles.
        Ensures that re-running identical queries updates entries instead of creating duplicates.
        """
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Extract msf_path and cves_list from details
            msf_path = details.module_name
            cves_list = details.cves

            # Serialize list values to JSON strings
            cves_json = json.dumps(cves_list)
            vulnerable_versions_json = json.dumps(data.vulnerable_versions)
            required_configs_json = json.dumps(data.required_configs)
            software_name = data.software_name or "Unknown"

            # Extract details fields
            mtype = details.type
            name = details.name
            module_name = details.module_name
            rank = details.rank
            disclosure_date = details.disclosure_date
            platform_json = json.dumps(details.platform)
            documentation = details.documentation
            raw_description = details.description

            # Execute UPSERT (INSERT OR REPLACE)
            cursor.execute(
                """
            INSERT OR REPLACE INTO vulnerabilities (
                msf_path, 
                cves, 
                software_name, 
                vulnerable_versions, 
                required_configs, 
                raw_description,
                type,
                name,
                module_name,
                rank,
                disclosure_date,
                platform,
                documentation
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
                (
                    msf_path,
                    cves_json,
                    software_name,
                    vulnerable_versions_json,
                    required_configs_json,
                    raw_description,
                    mtype,
                    name,
                    module_name,
                    rank,
                    disclosure_date,
                    platform_json,
                    documentation,
                ),
            )

            conn.commit()
        except Exception as e:
            self._logger.error(f"Error storing vulnerability entry for {msf_path}: {e}")
            if conn:
                conn.rollback()
            raise
        finally:
            if conn:
                conn.close()

    def get_vulnerability(self, msf_path: str) -> Optional[VulnerabilityRecord]:
        """
        Retrieves a vulnerability target profile by its Metasploit path.
        """
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT cves, software_name, vulnerable_versions, required_configs, raw_description,
                       type, name, module_name, rank, disclosure_date, platform, documentation
                FROM vulnerabilities 
                WHERE msf_path = ?
                """,
                (msf_path,),
            )
            row = cursor.fetchone()
            if not row:
                return None

            (
                raw_cves,
                software_name,
                raw_versions,
                raw_configs,
                raw_desc,
                mtype,
                name,
                module_name,
                rank,
                disclosure_date,
                raw_platform,
                documentation,
            ) = row
            return VulnerabilityRecord(
                msf_path=msf_path,
                cves=json.loads(raw_cves) if raw_cves else [],
                software_name=software_name,
                vulnerable_versions=json.loads(raw_versions) if raw_versions else [],
                required_configs=json.loads(raw_configs) if raw_configs else [],
                raw_description=raw_desc or "",
                type=mtype or "",
                name=name or "",
                module_name=module_name or "",
                rank=rank or "",
                disclosure_date=disclosure_date or "",
                platform=json.loads(raw_platform) if raw_platform else [],
                documentation=documentation or "",
            )
        except Exception as e:
            self._logger.error(
                f"Error retrieving vulnerability from SQLite repository: {e}"
            )
            return None
        finally:
            if conn:
                conn.close()

    def get_total_count(self) -> int:
        """
        Returns the total number of vulnerability target profiles stored.
        """
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM vulnerabilities;")
            return cursor.fetchone()[0]
        except Exception as e:
            self._logger.error(f"Error querying count from SQLite repository: {e}")
            return 0
        finally:
            if conn:
                conn.close()

    def get_top_technologies(self, limit: int = 10) -> List[Tuple[str, int]]:
        """
        Returns the top target technologies by vulnerability count.
        """
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT software_name, COUNT(*) as cnt 
                FROM vulnerabilities 
                GROUP BY software_name 
                ORDER BY cnt DESC 
                LIMIT ?;
                """,
                (limit,),
            )
            return cursor.fetchall()
        except Exception as e:
            self._logger.error(
                f"Error querying top technologies from SQLite repository: {e}"
            )
            return []
        finally:
            if conn:
                conn.close()
