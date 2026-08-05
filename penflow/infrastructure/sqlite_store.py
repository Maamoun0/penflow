import sqlite3
import json
import os
from typing import Dict, List, Any, Optional
from penflow.shared.utils import ensure_dir, get_utc_timestamp
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.infrastructure.sqlite")

class SQLiteKnowledgeStore:
    """
    SQLite Persistence Engine for PenFlow KnowledgeStore.
    Persists assets, observations, and findings across executions.
    """
    def __init__(self, db_path: str = "penflow.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS assets (
                    id TEXT PRIMARY KEY,
                    target_domain TEXT,
                    asset_value TEXT UNIQUE,
                    asset_type TEXT,
                    first_seen REAL,
                    last_seen REAL
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS observations (
                    id TEXT PRIMARY KEY,
                    asset_id TEXT,
                    obs_type TEXT,
                    data_json TEXT,
                    timestamp REAL
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS execution_plans (
                    id TEXT PRIMARY KEY,
                    target_domain TEXT,
                    plan_json TEXT,
                    created_at REAL
                )
            """)
            conn.commit()
            logger.info(f"[SQLiteKnowledgeStore] Initialized database at '{self.db_path}'")

    def save_asset(self, asset_id: str, target_domain: str, asset_value: str, asset_type: str = "subdomain") -> None:
        now = get_utc_timestamp()
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO assets (id, target_domain, asset_value, asset_type, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(asset_value) DO UPDATE SET last_seen=excluded.last_seen
            """, (asset_id, target_domain, asset_value, asset_type, now, now))
            conn.commit()

    def save_observation(self, obs_id: str, asset_id: str, obs_type: str, data: Dict[str, Any]) -> None:
        now = get_utc_timestamp()
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO observations (id, asset_id, obs_type, data_json, timestamp)
                VALUES (?, ?, ?, ?, ?)
            """, (obs_id, asset_id, obs_type, json.dumps(data, default=str), now))
            conn.commit()

    def get_assets_by_domain(self, target_domain: str) -> List[Dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, target_domain, asset_value, asset_type, first_seen, last_seen FROM assets WHERE target_domain = ?", (target_domain,))
            rows = cursor.fetchall()
            return [
                {"id": r[0], "target_domain": r[1], "asset_value": r[2], "asset_type": r[3], "first_seen": r[4], "last_seen": r[5]}
                for r in rows
            ]
