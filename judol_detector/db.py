"""Database manager - SQLite untuk tracking domain yang sudah dianalisis.

Menggunakan WAL mode untuk performa optimal di Raspberry Pi.
Menyimpan history semua domain yang sudah dianalisis agar tidak
perlu dikirim ulang ke DeepSeek.
"""

import sqlite3
import os
from datetime import datetime
from pathlib import Path
from typing import Optional
from contextlib import contextmanager


class Database:
    """SQLite database manager untuk Judol Detector."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        # Pastikan directory ada
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Buat koneksi database dengan optimasi untuk Raspberry Pi."""
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        # Optimasi untuk Raspberry Pi
        conn.execute("PRAGMA journal_mode=WAL")       # Write-Ahead Logging
        conn.execute("PRAGMA synchronous=NORMAL")     # Balance speed & safety
        conn.execute("PRAGMA cache_size=-8000")       # 8MB cache
        conn.execute("PRAGMA temp_store=MEMORY")      # Temp tables in memory
        conn.execute("PRAGMA mmap_size=67108864")     # 64MB memory-mapped I/O
        return conn

    @contextmanager
    def _connection(self):
        """Context manager untuk database connection."""
        conn = self._get_connection()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self):
        """Inisialisasi schema database."""
        with self._connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS analyzed_domains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT UNIQUE NOT NULL,
                    is_judol BOOLEAN NOT NULL DEFAULT 0,
                    confidence REAL NOT NULL DEFAULT 0.0,
                    reason TEXT DEFAULT '',
                    analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS blocked_domains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT UNIQUE NOT NULL,
                    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    unblocked_at TIMESTAMP DEFAULT NULL,
                    is_active BOOLEAN NOT NULL DEFAULT 1
                );

                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    total_queries INTEGER DEFAULT 0,
                    unique_domains INTEGER DEFAULT 0,
                    new_domains INTEGER DEFAULT 0,
                    detected_judol INTEGER DEFAULT 0,
                    blocked INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT
                );

                -- Index untuk query performa
                CREATE INDEX IF NOT EXISTS idx_analyzed_domain
                    ON analyzed_domains(domain);
                CREATE INDEX IF NOT EXISTS idx_analyzed_is_judol
                    ON analyzed_domains(is_judol);
                CREATE INDEX IF NOT EXISTS idx_blocked_domain
                    ON blocked_domains(domain);
                CREATE INDEX IF NOT EXISTS idx_blocked_active
                    ON blocked_domains(is_active);
                CREATE INDEX IF NOT EXISTS idx_scan_timestamp
                    ON scan_history(timestamp);
            """)

    # ---- Settings / Metadata ----

    def get_setting(self, key: str, default: str = None) -> Optional[str]:
        """Ambil value setting dari database."""
        with self._connection() as conn:
            row = conn.execute(
                "SELECT value FROM settings WHERE key = ?",
                (key,)
            ).fetchone()
            return row["value"] if row else default

    def set_setting(self, key: str, value: str):
        """Simpan/update value setting di database."""
        with self._connection() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                (key, str(value))
            )

    # ---- Analyzed Domains ----

    def is_domain_analyzed(self, domain: str) -> bool:
        """Cek apakah domain sudah pernah dianalisis."""
        with self._connection() as conn:
            row = conn.execute(
                "SELECT 1 FROM analyzed_domains WHERE domain = ?",
                (domain.lower(),)
            ).fetchone()
            return row is not None

    def get_unanalyzed_domains(self, domains: list[str]) -> list[str]:
        """Filter domain yang belum pernah dianalisis dari list yang diberikan.
        
        Ini adalah fungsi kunci untuk efisiensi - memastikan domain
        tidak dikirim ulang ke DeepSeek.
        """
        if not domains:
            return []
        
        domains_lower = [d.lower() for d in domains]
        
        with self._connection() as conn:
            # Gunakan temporary table untuk batch lookup yang efisien
            conn.execute("CREATE TEMP TABLE IF NOT EXISTS _check_domains (domain TEXT)")
            conn.execute("DELETE FROM _check_domains")
            conn.executemany(
                "INSERT INTO _check_domains (domain) VALUES (?)",
                [(d,) for d in domains_lower]
            )
            
            rows = conn.execute("""
                SELECT cd.domain FROM _check_domains cd
                LEFT JOIN analyzed_domains ad ON cd.domain = ad.domain
                WHERE ad.domain IS NULL
            """).fetchall()
            
            conn.execute("DROP TABLE IF EXISTS _check_domains")
            
            return [row["domain"] for row in rows]

    def save_analyzed_domains(self, domains: list[dict]):
        """Simpan hasil analisis domain.
        
        Args:
            domains: List of dict with keys: domain, is_judol, confidence, reason
        """
        if not domains:
            return
        
        with self._connection() as conn:
            conn.executemany(
                """INSERT OR REPLACE INTO analyzed_domains 
                   (domain, is_judol, confidence, reason, analyzed_at)
                   VALUES (?, ?, ?, ?, ?)""",
                [
                    (
                        d["domain"].lower(),
                        d["is_judol"],
                        d.get("confidence", 0.0),
                        d.get("reason", ""),
                        datetime.now().isoformat()
                    )
                    for d in domains
                ]
            )

    def get_all_judol_domains(self) -> list[dict]:
        """Ambil semua domain yang terdeteksi judol."""
        with self._connection() as conn:
            rows = conn.execute(
                """SELECT domain, confidence, reason, analyzed_at 
                   FROM analyzed_domains WHERE is_judol = 1
                   ORDER BY analyzed_at DESC"""
            ).fetchall()
            return [dict(row) for row in rows]

    def get_analyzed_count(self) -> dict:
        """Ambil statistik jumlah domain yang sudah dianalisis."""
        with self._connection() as conn:
            total = conn.execute("SELECT COUNT(*) FROM analyzed_domains").fetchone()[0]
            judol = conn.execute(
                "SELECT COUNT(*) FROM analyzed_domains WHERE is_judol = 1"
            ).fetchone()[0]
            safe = total - judol
            return {"total": total, "judol": judol, "safe": safe}

    # ---- Blocked Domains ----

    def save_blocked_domain(self, domain: str):
        """Catat domain yang diblokir."""
        with self._connection() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO blocked_domains (domain, blocked_at, is_active)
                   VALUES (?, ?, 1)""",
                (domain.lower(), datetime.now().isoformat())
            )

    def save_unblocked_domain(self, domain: str):
        """Catat domain yang di-unblock."""
        with self._connection() as conn:
            conn.execute(
                """UPDATE blocked_domains 
                   SET unblocked_at = ?, is_active = 0 
                   WHERE domain = ?""",
                (datetime.now().isoformat(), domain.lower())
            )

    def get_active_blocked_domains(self) -> list[str]:
        """Ambil semua domain yang aktif diblokir."""
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT domain FROM blocked_domains WHERE is_active = 1"
            ).fetchall()
            return [row["domain"] for row in rows]

    def is_domain_blocked(self, domain: str) -> bool:
        """Cek apakah domain sudah diblokir."""
        with self._connection() as conn:
            row = conn.execute(
                "SELECT 1 FROM blocked_domains WHERE domain = ? AND is_active = 1",
                (domain.lower(),)
            ).fetchone()
            return row is not None

    # ---- Scan History ----

    def save_scan_result(self, total_queries: int, unique_domains: int,
                         new_domains: int, detected_judol: int, blocked: int) -> int:
        """Simpan hasil scan dan return scan_id."""
        with self._connection() as conn:
            cursor = conn.execute(
                """INSERT INTO scan_history 
                   (timestamp, total_queries, unique_domains, new_domains, detected_judol, blocked)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    datetime.now().isoformat(),
                    total_queries, unique_domains, new_domains,
                    detected_judol, blocked
                )
            )
            return cursor.lastrowid

    def get_recent_scans(self, limit: int = 20) -> list[dict]:
        """Ambil history scan terbaru."""
        with self._connection() as conn:
            rows = conn.execute(
                """SELECT * FROM scan_history 
                   ORDER BY timestamp DESC LIMIT ?""",
                (limit,)
            ).fetchall()
            return [dict(row) for row in rows]

    def get_stats(self) -> dict:
        """Ambil statistik keseluruhan."""
        analyzed = self.get_analyzed_count()
        with self._connection() as conn:
            total_scans = conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]
            active_blocks = conn.execute(
                "SELECT COUNT(*) FROM blocked_domains WHERE is_active = 1"
            ).fetchone()[0]
        
        return {
            "total_scans": total_scans,
            "total_analyzed": analyzed["total"],
            "total_judol": analyzed["judol"],
            "total_safe": analyzed["safe"],
            "active_blocks": active_blocks,
        }
