"""
SQLite Database — Persistent storage for sessions, messages, and intelligence.

Uses aiosqlite for async operations with FastAPI.
"""

import os
import json
import aiosqlite
from datetime import datetime
from app.config import settings

# On Vercel serverless, the filesystem is read-only except /tmp
IS_SERVERLESS = os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME")
DB_PATH = "/tmp/honeypot.db" if IS_SERVERLESS else settings.DB_PATH


async def init_db():
    """Initialize database tables."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                status TEXT DEFAULT 'active',
                channel TEXT DEFAULT 'message',
                scam_type TEXT DEFAULT 'unknown',
                scam_confidence REAL DEFAULT 0.0,
                handoff_mode TEXT DEFAULT 'user',
                state TEXT DEFAULT 'INITIAL',
                turn_count INTEGER DEFAULT 0,
                total_extracted INTEGER DEFAULT 0,
                metadata TEXT DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                sender TEXT NOT NULL,
                text TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                state TEXT,
                channel TEXT DEFAULT 'message',
                FOREIGN KEY (session_id) REFERENCES sessions(session_id)
            );

            CREATE TABLE IF NOT EXISTS intelligence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                type TEXT NOT NULL,
                value TEXT NOT NULL,
                confidence REAL DEFAULT 0.0,
                context TEXT DEFAULT '',
                extracted_at TEXT NOT NULL,
                FOREIGN KEY (session_id) REFERENCES sessions(session_id)
            );

            CREATE TABLE IF NOT EXISTS handoff_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                from_mode TEXT NOT NULL,
                to_mode TEXT NOT NULL,
                reason TEXT DEFAULT '',
                scam_confidence REAL DEFAULT 0.0,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (session_id) REFERENCES sessions(session_id)
            );

            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                report_type TEXT DEFAULT 'pdf',
                file_path TEXT,
                generated_at TEXT NOT NULL,
                FOREIGN KEY (session_id) REFERENCES sessions(session_id)
            );
        """)
        await db.commit()


async def create_session(session_id: str, channel: str = "message") -> dict:
    now = datetime.now().isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT OR IGNORE INTO sessions (session_id, created_at, updated_at, channel) VALUES (?, ?, ?, ?)",
            (session_id, now, now, channel),
        )
        await db.commit()
    return {"session_id": session_id, "created_at": now}


async def update_session(session_id: str, **kwargs):
    now = datetime.now().isoformat()
    fields = ["updated_at=?"]
    values = [now]
    for key, val in kwargs.items():
        if key in ("status", "scam_type", "scam_confidence", "handoff_mode", "state", "turn_count", "total_extracted", "metadata"):
            fields.append(f"{key}=?")
            values.append(json.dumps(val) if isinstance(val, dict) else val)
    values.append(session_id)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            f"UPDATE sessions SET {', '.join(fields)} WHERE session_id=?",
            values,
        )
        await db.commit()


async def save_message(session_id: str, sender: str, text: str, state: str = "", channel: str = "message"):
    now = datetime.now().isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO messages (session_id, sender, text, timestamp, state, channel) VALUES (?, ?, ?, ?, ?, ?)",
            (session_id, sender, text, now, state, channel),
        )
        await db.commit()


async def save_intelligence(session_id: str, items: list[dict]):
    now = datetime.now().isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        for item in items:
            await db.execute(
                "INSERT INTO intelligence (session_id, type, value, confidence, context, extracted_at) VALUES (?, ?, ?, ?, ?, ?)",
                (session_id, item["type"], item["value"], item.get("confidence", 0), item.get("context", ""), now),
            )
        await db.commit()


async def save_handoff_event(session_id: str, from_mode: str, to_mode: str, reason: str, confidence: float):
    now = datetime.now().isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO handoff_events (session_id, from_mode, to_mode, reason, scam_confidence, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
            (session_id, from_mode, to_mode, reason, confidence, now),
        )
        await db.commit()


async def get_session(session_id: str) -> dict | None:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM sessions WHERE session_id=?", (session_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None


async def get_messages(session_id: str) -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM messages WHERE session_id=? ORDER BY timestamp",
            (session_id,),
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def get_intelligence(session_id: str) -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM intelligence WHERE session_id=? ORDER BY extracted_at",
            (session_id,),
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def get_all_sessions(limit: int = 50) -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM sessions ORDER BY updated_at DESC LIMIT ?",
            (limit,),
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def get_dashboard_stats() -> dict:
    async with aiosqlite.connect(DB_PATH) as db:
        total = (await (await db.execute("SELECT COUNT(*) FROM sessions")).fetchone())[0]
        active = (await (await db.execute("SELECT COUNT(*) FROM sessions WHERE status='active'")).fetchone())[0]
        scams = (await (await db.execute("SELECT COUNT(*) FROM sessions WHERE scam_confidence >= 0.35")).fetchone())[0]
        intel_count = (await (await db.execute("SELECT COUNT(*) FROM intelligence")).fetchone())[0]
        msg_count = (await (await db.execute("SELECT COUNT(*) FROM messages")).fetchone())[0]
        return {
            "total_sessions": total,
            "active_sessions": active,
            "scams_detected": scams,
            "intelligence_items": intel_count,
            "total_messages": msg_count,
        }
