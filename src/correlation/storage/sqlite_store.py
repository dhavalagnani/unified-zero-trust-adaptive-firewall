"""
src/correlation/storage/sqlite_store.py

Purpose: SQLite-based storage for security events and correlations
Context: Persists events for historical analysis, auditing, and machine learning

Schema:
- events: Raw security events
- correlations: Detected threat correlations
- rules: Generated firewall rules
"""

import sqlite3
import logging
import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional
import aiosqlite

logger = logging.getLogger(__name__)


class EventStore:
    """SQLite storage for security events and correlations"""
    
    def __init__(self, db_path: str = "/var/lib/uztaf/correlation.db"):
        """Initialize event store"""
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        logger.info(f"Event store initialized: {db_path}")
    
    async def init_db(self):
        """Initialize database schema"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    dest_ip TEXT NOT NULL,
                    source_port INTEGER,
                    dest_port INTEGER,
                    protocol TEXT,
                    event_type TEXT NOT NULL,
                    severity TEXT,
                    source TEXT,
                    metadata TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            await db.execute("""
                CREATE TABLE IF NOT EXISTS correlations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    threat_id TEXT UNIQUE NOT NULL,
                    threat_type TEXT NOT NULL,
                    confidence_score REAL,
                    involved_ips TEXT,
                    recommended_action TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            await db.execute("""
                CREATE TABLE IF NOT EXISTS rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id TEXT UNIQUE NOT NULL,
                    action TEXT NOT NULL,
                    source_ip TEXT,
                    dest_ip TEXT,
                    protocol TEXT,
                    expires_at TEXT,
                    metadata TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indices for faster queries
            await db.execute("CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type)")
            
            await db.commit()
        
        logger.info("Database schema initialized")
    
    async def store_event(self, event) -> int:
        """Store a security event"""
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute("""
                INSERT INTO events (timestamp, source_ip, dest_ip, source_port, dest_port,
                                    protocol, event_type, severity, source, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.timestamp.isoformat(),
                event.source_ip,
                event.dest_ip,
                event.source_port,
                event.dest_port,
                event.protocol,
                event.event_type,
                event.severity,
                event.source,
                json.dumps(event.metadata)
            ))
            await db.commit()
            return cursor.lastrowid
    
    async def query_events(self, source_ip: Optional[str] = None, 
                          event_type: Optional[str] = None,
                          limit: int = 100) -> List:
        """Query events with filters"""
        async with aiosqlite.connect(self.db_path) as db:
            query = "SELECT * FROM events WHERE 1=1"
            params = []
            
            if source_ip:
                query += " AND source_ip = ?"
                params.append(source_ip)
            
            if event_type:
                query += " AND event_type = ?"
                params.append(event_type)
            
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            
            cursor = await db.execute(query, params)
            return await cursor.fetchall()
    
    async def close(self):
        """Close the database connection"""
        logger.info("Event store closed")


if __name__ == "__main__":
    import asyncio
    
    async def test():
        store = EventStore("/tmp/test.db")
        await store.init_db()
        print("Database initialized")
    
    asyncio.run(test())
