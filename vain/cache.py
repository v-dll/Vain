"""SQLite key/value cache with per-entry TTL.

Used by plugins that call external APIs (NVD, EPSS, Shodan) to survive rate
limits and speed up repeat scans. If the database cannot be opened, the cache
silently degrades to "always miss" so a scan never fails because of it.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

DEFAULT_TTL = 24 * 3600


class Cache:
    def __init__(self, path: Path | str | None, default_ttl: int = DEFAULT_TTL):
        self.default_ttl = default_ttl
        self.path = None if path is None else Path(path)
        self._conn: sqlite3.Connection | None = None
        try:
            self._conn = sqlite3.connect(":memory:" if self.path is None else str(self.path))
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS cache ("
                " namespace TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL,"
                " created_at REAL NOT NULL, expires_at REAL NOT NULL,"
                " PRIMARY KEY (namespace, key))"
            )
            self._conn.commit()
        except sqlite3.Error:
            self._conn = None

    @property
    def available(self) -> bool:
        return self._conn is not None

    def get(self, namespace: str, key: str, default: Any = None) -> Any:
        if not self._conn:
            return default
        try:
            row = self._conn.execute(
                "SELECT value, expires_at FROM cache WHERE namespace=? AND key=?", (namespace, key)
            ).fetchone()
            if not row or row[1] < time.time():
                return default
            return json.loads(row[0])
        except (sqlite3.Error, ValueError):
            return default

    def set(self, namespace: str, key: str, value: Any, ttl: int | None = None) -> None:
        if not self._conn:
            return
        now = time.time()
        try:
            self._conn.execute(
                "INSERT OR REPLACE INTO cache VALUES (?,?,?,?,?)",
                (namespace, key, json.dumps(value), now, now + (self.default_ttl if ttl is None else ttl)),
            )
            self._conn.commit()
        except (sqlite3.Error, TypeError):
            pass

    def stats(self) -> dict:
        if not self._conn:
            return {"available": False, "entries": 0, "expired": 0, "namespaces": {}, "bytes": 0}
        now = time.time()
        total, expired = self._conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(expires_at < ?), 0) FROM cache", (now,)
        ).fetchone()
        namespaces = dict(self._conn.execute("SELECT namespace, COUNT(*) FROM cache GROUP BY namespace"))
        size = self.path.stat().st_size if self.path and self.path.exists() else 0
        return {"available": True, "entries": total, "expired": int(expired), "namespaces": namespaces, "bytes": size}

    def clear(self, namespace: str | None = None) -> int:
        if not self._conn:
            return 0
        cur = (
            self._conn.execute("DELETE FROM cache WHERE namespace=?", (namespace,))
            if namespace
            else self._conn.execute("DELETE FROM cache")
        )
        self._conn.commit()
        return cur.rowcount

    def purge_expired(self) -> int:
        if not self._conn:
            return 0
        cur = self._conn.execute("DELETE FROM cache WHERE expires_at < ?", (time.time(),))
        self._conn.commit()
        return cur.rowcount
