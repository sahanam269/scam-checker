# database.py
import os
import sqlite3
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "scam_checker.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create the table if it doesn't exist yet."""
    conn = get_connection()
    try:
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS checks (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT    NOT NULL,
                    score      INTEGER NOT NULL,
                    level      TEXT    NOT NULL,
                    categories TEXT    NOT NULL
                )
            """)
    finally:
        conn.close()


def save_check(result):
    """Save ONLY the summary, never the user's message."""
    categories = ", ".join(sorted({f["category"] for f in result["findings"]}))
    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    conn = get_connection()
    try:
        with conn:
            conn.execute(
                "INSERT INTO checks (created_at, score, level, categories) VALUES (?, ?, ?, ?)",
                (created_at, result["score"], result["level"], categories or "None"),
            )
    finally:
        conn.close()


def get_recent(limit=20):
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT created_at, score, level, categories FROM checks ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_stats():
    conn = get_connection()
    try:
        total = conn.execute("SELECT COUNT(*) FROM checks").fetchone()[0]
        average = conn.execute("SELECT AVG(score) FROM checks").fetchone()[0] or 0
        rows = conn.execute("SELECT level, COUNT(*) AS n FROM checks GROUP BY level").fetchall()
        by_level = {r["level"]: r["n"] for r in rows}
        return {"total": total, "average": round(average, 1), "by_level": by_level}
    finally:
        conn.close()