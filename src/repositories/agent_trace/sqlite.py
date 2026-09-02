import logging
from typing import List, Optional, Tuple, Dict, Any
from database import DatabaseManager
from models import AgentTraceRecord, MSFModuleRecord
from .base import AgentTraceRepository


class SQLiteAgentTraceRepository(AgentTraceRepository):
    """
    SQLite implementation of AgentTraceRepository.
    """

    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
        self._logger = logging.getLogger(self.__class__.__name__)

    def save(self, record: AgentTraceRecord) -> Optional[int]:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO agent_traces (
                    msf_path, agent_name, status, failed_step_name,
                    failed_step_index, error_category, error_message,
                    diagnostic_hint, duration_seconds, total_tokens,
                    prompt_tokens, completion_tokens, trace_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    record.msf_path,
                    record.agent_name,
                    record.status,
                    record.failed_step_name,
                    record.failed_step_index,
                    record.error_category,
                    record.error_message,
                    record.diagnostic_hint,
                    record.duration_seconds,
                    record.total_tokens if record.total_tokens is not None else 0,
                    record.prompt_tokens if record.prompt_tokens is not None else 0,
                    (
                        record.completion_tokens
                        if record.completion_tokens is not None
                        else 0
                    ),
                    record.trace_json,
                ),
            )
            conn.commit()
            return cursor.lastrowid
        except Exception as e:
            self._logger.error(
                f"Error saving agent trace record for '{record.msf_path}': {e}"
            )
            return None
        finally:
            if conn:
                conn.close()

    def get_by_path(self, msf_path: str) -> List[AgentTraceRecord]:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, msf_path, agent_name, status, failed_step_name,
                       failed_step_index, error_category, error_message,
                       diagnostic_hint, duration_seconds, total_tokens,
                       prompt_tokens, completion_tokens, trace_json, created_at
                FROM agent_traces
                WHERE msf_path = ?
                ORDER BY id ASC;
                """,
                (msf_path,),
            )
            rows = cursor.fetchall()
            return [
                AgentTraceRecord(
                    id=r[0],
                    msf_path=r[1],
                    agent_name=r[2],
                    status=r[3],
                    failed_step_name=r[4],
                    failed_step_index=r[5],
                    error_category=r[6],
                    error_message=r[7],
                    diagnostic_hint=r[8],
                    duration_seconds=r[9],
                    total_tokens=r[10],
                    prompt_tokens=r[11],
                    completion_tokens=r[12],
                    trace_json=r[13],
                    created_at=r[14],
                )
                for r in rows
            ]
        except Exception as e:
            self._logger.error(f"Error getting agent traces for path '{msf_path}': {e}")
            return []
        finally:
            if conn:
                conn.close()

    def get_latest_by_path(
        self, msf_path: str, agent_name: Optional[str] = None
    ) -> Optional[AgentTraceRecord]:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            if agent_name:
                cursor.execute(
                    """
                    SELECT id, msf_path, agent_name, status, failed_step_name,
                           failed_step_index, error_category, error_message,
                           diagnostic_hint, duration_seconds, total_tokens,
                           prompt_tokens, completion_tokens, trace_json, created_at
                    FROM agent_traces
                    WHERE msf_path = ? AND agent_name = ?
                    ORDER BY id DESC LIMIT 1;
                    """,
                    (msf_path, agent_name),
                )
            else:
                cursor.execute(
                    """
                    SELECT id, msf_path, agent_name, status, failed_step_name,
                           failed_step_index, error_category, error_message,
                           diagnostic_hint, duration_seconds, total_tokens,
                           prompt_tokens, completion_tokens, trace_json, created_at
                    FROM agent_traces
                    WHERE msf_path = ?
                    ORDER BY id DESC LIMIT 1;
                    """,
                    (msf_path,),
                )
            r = cursor.fetchone()
            if not r:
                return None
            return AgentTraceRecord(
                id=r[0],
                msf_path=r[1],
                agent_name=r[2],
                status=r[3],
                failed_step_name=r[4],
                failed_step_index=r[5],
                error_category=r[6],
                error_message=r[7],
                diagnostic_hint=r[8],
                duration_seconds=r[9],
                total_tokens=r[10],
                prompt_tokens=r[11],
                completion_tokens=r[12],
                trace_json=r[13],
                created_at=r[14],
            )
        except Exception as e:
            self._logger.error(
                f"Error getting latest agent trace for path '{msf_path}': {e}"
            )
            return None
        finally:
            if conn:
                conn.close()

    def get_failed_traces(
        self,
        pattern: Optional[str] = None,
        platform: Optional[str] = None,
        agent_name: Optional[str] = None,
        error_category: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[Tuple[AgentTraceRecord, Optional[MSFModuleRecord]]]:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()

            query = """
                SELECT 
                    t.id, t.msf_path, t.agent_name, t.status, t.failed_step_name,
                    t.failed_step_index, t.error_category, t.error_message,
                    t.diagnostic_hint, t.duration_seconds, t.total_tokens,
                    t.prompt_tokens, t.completion_tokens, t.trace_json, t.created_at,
                    m.id AS m_id, m.display_name, m.type, m.rank, m.disclosure_date,
                    (SELECT group_concat(mp.platform) FROM module_platforms mp WHERE mp.module_path = m.path) AS platforms,
                    m.documentation, m.description
                FROM agent_traces t
                LEFT JOIN msf_modules m ON t.msf_path = m.path
                WHERE t.status = 'FAILED'
            """
            params: List[Any] = []

            if pattern:
                sql_pat = pattern.replace("*", "%")
                if not ("%" in sql_pat):
                    sql_pat = f"%{sql_pat}%"
                query += " AND (t.msf_path LIKE ? OR (m.display_name IS NOT NULL AND m.display_name LIKE ?))"
                params.extend([sql_pat, sql_pat])

            if platform:
                query += " AND EXISTS (SELECT 1 FROM module_platforms mp WHERE mp.module_path = t.msf_path AND mp.platform LIKE ?)"
                params.append(f"%{platform}%")

            if agent_name:
                query += " AND t.agent_name LIKE ?"
                params.append(f"%{agent_name}%")

            if error_category:
                query += " AND t.error_category LIKE ?"
                params.append(f"%{error_category}%")

            query += " ORDER BY t.id DESC"

            if limit and limit > 0:
                query += f" LIMIT {int(limit)}"

            cursor.execute(query, params)
            rows = cursor.fetchall()

            results: List[Tuple[AgentTraceRecord, Optional[MSFModuleRecord]]] = []
            for r in rows:
                trace_rec = AgentTraceRecord(
                    id=r[0],
                    msf_path=r[1],
                    agent_name=r[2],
                    status=r[3],
                    failed_step_name=r[4],
                    failed_step_index=r[5],
                    error_category=r[6],
                    error_message=r[7],
                    diagnostic_hint=r[8],
                    duration_seconds=r[9],
                    total_tokens=r[10],
                    prompt_tokens=r[11],
                    completion_tokens=r[12],
                    trace_json=r[13],
                    created_at=r[14],
                )
                module_rec = None
                if r[15] is not None:
                    plat_str = r[20] or ""
                    platforms = [p.strip() for p in plat_str.split(",") if p.strip()]
                    module_rec = MSFModuleRecord(
                        id=r[15],
                        path=r[1],
                        display_name=r[16] or "",
                        type=r[17] or "",
                        rank=r[18] or "",
                        disclosure_date=r[19] or "",
                        platforms=platforms,
                        documentation=r[21] or "",
                        description=r[22] or "",
                    )
                results.append((trace_rec, module_rec))
            return results
        except Exception as e:
            self._logger.error(f"Error querying failed agent traces: {e}")
            return []
        finally:
            if conn:
                conn.close()

    def get_failure_statistics(self) -> Dict[str, Any]:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) FROM agent_traces;")
            total_traces = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM agent_traces WHERE status = 'FAILED';")
            total_failures = cursor.fetchone()[0]

            cursor.execute(
                "SELECT COUNT(*) FROM agent_traces WHERE status = 'SUCCESS';"
            )
            total_success = cursor.fetchone()[0]

            cursor.execute(
                """
                SELECT agent_name, COUNT(*) as cnt 
                FROM agent_traces 
                WHERE status = 'FAILED' 
                GROUP BY agent_name 
                ORDER BY cnt DESC;
                """
            )
            failures_by_agent = {r[0]: r[1] for r in cursor.fetchall()}

            cursor.execute(
                """
                SELECT error_category, COUNT(*) as cnt 
                FROM agent_traces 
                WHERE status = 'FAILED' AND error_category IS NOT NULL 
                GROUP BY error_category 
                ORDER BY cnt DESC;
                """
            )
            failures_by_category = {r[0]: r[1] for r in cursor.fetchall()}

            return {
                "total_traces": total_traces,
                "total_failures": total_failures,
                "total_success": total_success,
                "failures_by_agent": failures_by_agent,
                "failures_by_category": failures_by_category,
            }
        except Exception as e:
            self._logger.error(f"Error retrieving failure statistics: {e}")
            return {
                "total_traces": 0,
                "total_failures": 0,
                "total_success": 0,
                "failures_by_agent": {},
                "failures_by_category": {},
            }
        finally:
            if conn:
                conn.close()

    def get_all_traces(
        self,
        pattern: Optional[str] = None,
        agent_name: Optional[str] = None,
        status: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[AgentTraceRecord]:
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()

            query = """
                SELECT id, msf_path, agent_name, status, failed_step_name,
                       failed_step_index, error_category, error_message,
                       diagnostic_hint, duration_seconds, total_tokens,
                       prompt_tokens, completion_tokens, trace_json, created_at
                FROM agent_traces
                WHERE 1=1
            """
            params: List[Any] = []

            if pattern:
                sql_pat = pattern.replace("*", "%")
                if not ("%" in sql_pat):
                    sql_pat = f"%{sql_pat}%"
                query += " AND msf_path LIKE ?"
                params.append(sql_pat)

            if agent_name:
                query += " AND agent_name LIKE ?"
                params.append(f"%{agent_name}%")

            if status:
                query += " AND UPPER(status) = ?"
                params.append(status.upper())

            query += " ORDER BY id ASC"

            if limit and limit > 0:
                query += f" LIMIT {int(limit)}"

            cursor.execute(query, params)
            rows = cursor.fetchall()

            return [
                AgentTraceRecord(
                    id=r[0],
                    msf_path=r[1],
                    agent_name=r[2],
                    status=r[3],
                    failed_step_name=r[4],
                    failed_step_index=r[5],
                    error_category=r[6],
                    error_message=r[7],
                    diagnostic_hint=r[8],
                    duration_seconds=r[9],
                    total_tokens=r[10],
                    prompt_tokens=r[11],
                    completion_tokens=r[12],
                    trace_json=r[13],
                    created_at=r[14],
                )
                for r in rows
            ]
        except Exception as e:
            self._logger.error(f"Error querying all agent traces: {e}")
            return []
        finally:
            if conn:
                conn.close()
