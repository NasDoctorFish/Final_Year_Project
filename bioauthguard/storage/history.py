"""Persist test runs to SQLite for the dashboard and trend tracking."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing

from ..models import TestRun

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id            TEXT PRIMARY KEY,
    package       TEXT NOT NULL,
    started_at    REAL NOT NULL,
    finished_at   REAL,
    critical      INTEGER DEFAULT 0,
    high          INTEGER DEFAULT 0,
    medium        INTEGER DEFAULT 0,
    low           INTEGER DEFAULT 0,
    info          INTEGER DEFAULT 0,
    payload       TEXT NOT NULL
);
"""


class History:
    def __init__(self, database: str):
        self.database = database
        with closing(sqlite3.connect(self.database)) as conn:
            conn.executescript(_SCHEMA)
            conn.commit()

    def save(self, run: TestRun) -> None:
        counts = run.counts()
        with closing(sqlite3.connect(self.database)) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO runs "
                "(id, package, started_at, finished_at, critical, high, medium, low, info, payload) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    run.id, run.package, run.started_at, run.finished_at,
                    counts["Critical"], counts["High"], counts["Medium"],
                    counts["Low"], counts["Info"], json.dumps(run.to_dict()),
                ),
            )
            conn.commit()

    def list_runs(self, limit: int = 100) -> list[dict]:
        with closing(sqlite3.connect(self.database)) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT id, package, started_at, finished_at, critical, high, medium, low, info "
                "FROM runs ORDER BY started_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]

    def get(self, run_id: str) -> dict | None:
        with closing(sqlite3.connect(self.database)) as conn:
            row = conn.execute("SELECT payload FROM runs WHERE id = ?", (run_id,)).fetchone()
            return json.loads(row[0]) if row else None
