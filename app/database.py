import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator
from app.config import DATABASE_URL


def _sqlite_path() -> str:
    if not DATABASE_URL.startswith("sqlite:///"):
        raise ValueError("This starter project supports sqlite:/// URLs only.")
    return DATABASE_URL.replace("sqlite:///", "", 1)


DB_PATH = _sqlite_path()


@contextmanager
def get_conn() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    path = Path(DB_PATH)
    if path.parent and str(path.parent) != ".":
        path.parent.mkdir(parents=True, exist_ok=True)

    with get_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS reviews (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                language TEXT NOT NULL,
                mode TEXT NOT NULL,
                code TEXT NOT NULL,
                issues_json TEXT NOT NULL,
                llm_summary TEXT NOT NULL,
                ai_review_json TEXT,
                risk_score INTEGER NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        columns = {row[1] for row in conn.execute("PRAGMA table_info(reviews)").fetchall()}
        if "ai_review_json" not in columns:
            conn.execute("ALTER TABLE reviews ADD COLUMN ai_review_json TEXT")


def save_review(filename: str, language: str, mode: str, code: str, issues: list[dict], llm_summary: str, ai_review: dict | None, risk_score: int) -> dict:
    init_db()
    created_at = datetime.now(timezone.utc).isoformat()
    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO reviews (filename, language, mode, code, issues_json, llm_summary, ai_review_json, risk_score, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (filename, language, mode, code, json.dumps(issues), llm_summary, json.dumps(ai_review) if ai_review is not None else None, risk_score, created_at),
        )
        review_id = cur.lastrowid
    return get_review(review_id)


def get_review(review_id: int) -> dict:
    init_db()
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM reviews WHERE id = ?", (review_id,)).fetchone()
    if row is None:
        return {}
    data = dict(row)
    data["issues"] = json.loads(data.pop("issues_json"))
    ai_review_json = data.pop("ai_review_json", None)
    data["ai_review"] = json.loads(ai_review_json) if ai_review_json else None
    return data


def list_reviews(limit: int = 20) -> list[dict]:
    init_db()
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT id, filename, language, risk_score, created_at, issues_json
            FROM reviews
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        item["total_issues"] = len(json.loads(item.pop("issues_json")))
        result.append(item)
    return result
