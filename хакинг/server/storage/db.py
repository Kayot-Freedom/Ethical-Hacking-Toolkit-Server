import aiosqlite
import json
from datetime import datetime
from core.config import DB_PATH


async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                created_at TEXT NOT NULL,
                data TEXT NOT NULL
            )
        """)
        await db.execute("CREATE INDEX IF NOT EXISTS idx_target ON scans(target, created_at DESC)")
        await db.commit()


async def save_scan(target: str, data: dict) -> int:
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "INSERT INTO scans (target, created_at, data) VALUES (?, ?, ?)",
            (target, datetime.utcnow().isoformat(), json.dumps(data)),
        )
        await db.commit()
        return cur.lastrowid


async def get_scans(target: str, limit: int = 10) -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT id, target, created_at, data FROM scans WHERE target = ? ORDER BY created_at DESC LIMIT ?",
            (target, limit),
        )
        rows = await cur.fetchall()
        return [
            {"id": r["id"], "target": r["target"],
             "created_at": r["created_at"], "data": json.loads(r["data"])}
            for r in rows
        ]


async def get_last_scan(target: str, exclude_id: int | None = None) -> dict | None:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        if exclude_id:
            cur = await db.execute(
                "SELECT * FROM scans WHERE target = ? AND id != ? ORDER BY created_at DESC LIMIT 1",
                (target, exclude_id),
            )
        else:
            cur = await db.execute(
                "SELECT * FROM scans WHERE target = ? ORDER BY created_at DESC LIMIT 1",
                (target,),
            )
        row = await cur.fetchone()
        if not row:
            return None
        return {"id": row["id"], "target": row["target"],
                "created_at": row["created_at"], "data": json.loads(row["data"])}