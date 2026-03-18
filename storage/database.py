"""
Argos — Database Manager
Maneja la conexión a SQLite para la persistencia del inventario de red
y el historial de auditoría.
"""

import sqlite3
import datetime
from typing import List, Dict, Optional


class DatabaseManager:
    """Clase para interactuar con la base de datos SQLite."""

    def __init__(self, db_path: str = "argos_audit.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Devuelve una conexión a la base de datos."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Inicializa las tablas si no existen."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Tabla de escaneos (historial)
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

            # Tabla de dispositivos (inventario)
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

            # Tabla de registro de presencia por IP y MAC
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

    def save_scan(self, network_cidr: str, scan_method: str, duration: float, devices: List[Dict]) -> bool:
        """
        Guarda el resultado de un escaneo en la base de datos y actualiza
        el inventario de dispositivos.
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                now = datetime.datetime.now().isoformat()

                # 1. Insertar metadatos del escaneo
                cursor.execute(
                    '''INSERT INTO scan_history (timestamp, network_cidr, scan_method, duration_sec, devices_found) 
                       VALUES (?, ?, ?, ?, ?)''',
                    (now, network_cidr, scan_method, duration, len(devices))
                )
                scan_id = cursor.lastrowid

                # 2. Actualizar inventario e insertar presencia
                for d in devices:
                    ip = d.get('ip')
                    mac = d.get('mac', 'N/A')
                    hostname = d.get('hostname', 'Desconocido')
                    vendor = d.get('vendor', '')
                    latency = d.get('latency_ms', 0.0)

                    # Usar MAC o IP como fallback si no hay MAC
                    identifier = mac if mac != 'N/A' else f"IP-{ip}"

                    # Hacer un upsert en devices
                    cursor.execute('''
                        INSERT INTO devices (mac, ip, hostname, vendor, first_seen, last_seen)
                        VALUES (?, ?, ?, ?, ?, ?)
                        ON CONFLICT(mac) DO UPDATE SET
                            ip=excluded.ip,
                            hostname=CASE WHEN excluded.hostname != 'Desconocido' THEN excluded.hostname ELSE devices.hostname END,
                            last_seen=excluded.last_seen
                    ''', (identifier, ip, hostname, vendor, now, now))

                    # Registrar la presencia en este escaneo
                    cursor.execute('''
                        INSERT INTO device_presence (scan_id, mac, ip, latency_ms)
                        VALUES (?, ?, ?, ?)
                    ''', (scan_id, identifier, ip, latency))

                conn.commit()
            return True
        except Exception as e:
            print(f"Error guardando escaneo en BD: {e}")
            return False

    def get_recent_scans(self, limit: int = 5) -> List[Dict]:
        """Obtiene el historial de los últimos escaneos."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scan_history ORDER BY id DESC LIMIT ?", (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def get_inventory(self) -> List[Dict]:
        """Obtiene el inventario completo de dispositivos."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM devices ORDER BY last_seen DESC")
            return [dict(row) for row in cursor.fetchall()]

# Instancia global por defecto
db = DatabaseManager()
