"""Persistence layer for ShipGuard findings using SQLite."""

import sqlite3
import datetime
from pathlib import Path
from typing import List, Optional

from shipguard.models import Finding, Severity

class Database:
    """Handles storage and retrieval of finding states."""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    rule_id TEXT,
                    severity TEXT,
                    file_path TEXT,
                    line_number INTEGER,
                    message TEXT,
                    status TEXT DEFAULT 'open',
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP,
                    ai_triage_reason TEXT
                )
            """)
            conn.commit()

    def sync_findings(self, findings: List[Finding]):
        """Updates the database with the latest scan findings."""
        now = datetime.datetime.now().isoformat()
        with self._get_connection() as conn:
            for f in findings:
                # Create a unique hash for the finding to track its identity across scans
                finding_id = f"{f.rule_id}:{f.file_path}:{f.line_number}"
                
                conn.execute("""
                    INSERT INTO findings (id, rule_id, severity, file_path, line_number, message, first_seen, last_seen, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open')
                    ON CONFLICT(id) DO UPDATE SET
                        last_seen = excluded.last_seen,
                        status = 'open' WHERE status = 'fixed'
                """, (finding_id, f.rule_id, f.severity.value, str(f.file_path), f.line_number, f.message, now, now))
            
            # Mark findings not seen in this scan as potentially fixed
            seen_ids = [f"{f.rule_id}:{f.file_path}:{f.line_number}" for f in findings]
            if seen_ids:
                placeholders = ",".join("?" for _ in seen_ids)
                query = "UPDATE findings SET status = 'fixed' WHERE id NOT IN (" + placeholders + ") AND status = 'open'"
                conn.execute(query, seen_ids)
            else:
                conn.execute("UPDATE findings SET status = 'fixed' WHERE status = 'open'")
            
            conn.commit()

    def get_open_findings(self) -> List[dict]:
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM findings WHERE status = 'open'")
            return [dict(row) for row in cursor.fetchall()]
