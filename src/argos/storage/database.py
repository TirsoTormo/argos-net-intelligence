"""
Argos — Database Manager
Handles SQLite connection for network inventory persistence
and audit history.
"""

import sqlite3
import datetime
import json
from typing import List, Dict, Optional, Any
from argos.core.models import DeviceModel, ScanResultModel


class DatabaseManager:
    """Class to interact with the SQLite database."""

    def __init__(self, db_path: str = "argos_audit.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Returns a database connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Initializes tables if they do not exist."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Scan history table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    network_cidr TEXT NOT NULL,
                    scan_method TEXT,
                    duration_sec REAL,
                    devices_found INTEGER
                )
            ''')

            # Devices table (inventory)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS devices (
                    mac TEXT PRIMARY KEY,
                    ip TEXT NOT NULL,
                    hostname TEXT,
                    vendor TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL
                )
            ''')

            # Presence log by IP and MAC
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS device_presence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    mac TEXT,
                    ip TEXT,
                    latency_ms REAL,
                    FOREIGN KEY(scan_id) REFERENCES scan_history(id),
                    FOREIGN KEY(mac) REFERENCES devices(mac)
                )
            ''')

            conn.commit()

    def save_scan(self, scan: ScanResultModel) -> bool:
        """
        Saves a scan result (Pydantic model) to the database.
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                now = scan.timestamp.isoformat()

                # 1. Insert scan metadata
                cursor.execute(
                    '''INSERT INTO scan_history (timestamp, network_cidr, scan_method, duration_sec, devices_found) 
                       VALUES (?, ?, ?, ?, ?)''',
                    (now, scan.network_cidr, scan.scan_method, scan.duration_sec, scan.devices_found)
                )
                scan_id = cursor.lastrowid

                # 2. Update inventory and insert presence
                for d in scan.devices:
                    ip = d.ip
                    mac = d.mac
                    hostname = d.hostname
                    vendor = d.vendor
                    latency = d.latency_ms or 0.0

                    # Use MAC or IP fallback
                    identifier = mac if mac != 'N/A' else f"IP-{ip}"

                    # Upsert on devices
                    cursor.execute('''
                        INSERT INTO devices (mac, ip, hostname, vendor, first_seen, last_seen)
                        VALUES (?, ?, ?, ?, ?, ?)
                        ON CONFLICT(mac) DO UPDATE SET
                            ip=excluded.ip,
                            hostname=CASE 
                                WHEN excluded.hostname != 'Unknown' THEN excluded.hostname 
                                ELSE devices.hostname 
                            END,
                            last_seen=excluded.last_seen
                    ''', (identifier, ip, hostname, vendor, now, now))

                    # Log presence
                    cursor.execute('''
                        INSERT INTO device_presence (scan_id, mac, ip, latency_ms)
                        VALUES (?, ?, ?, ?)
                    ''', (scan_id, identifier, ip, latency))

                conn.commit()
            return True
        except Exception as e:
            print(f"Error saving scan to DB: {e}")
            return False

    def get_recent_scans(self, limit: int = 5) -> List[Dict]:
        """Gets history of recent scans."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scan_history ORDER BY id DESC LIMIT ?", (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def get_inventory(self) -> List[Dict]:
        """Gets complete device inventory."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM devices ORDER BY last_seen DESC")
            return [dict(row) for row in cursor.fetchall()]

# Global default instance
db = DatabaseManager()
