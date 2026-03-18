"""
Argos — Exportador de Reportes
Módulo para exportar los resultados de los escaneos a múltiples formatos
como JSON, Markdown y CSV para auditorías profesionales.
"""

import json
import csv
import datetime
from typing import List, Dict, Any


class ReportExporter:
    """Clase para manejar las exportaciones de datos de red."""

    @staticmethod
    def _get_timestamp() -> str:
        """Devuelve el timestamp actual en formato ISO 8601."""
        return datetime.datetime.now().isoformat()

    @classmethod
    def to_json(
        cls,
        filepath: str,
        devices: List[Dict],
        network_cidr: str,
        scan_method: str = "ARP",
        duration: float = 0.0,
    ) -> bool:
        """
        Exporta los resultados a un archivo JSON estructurado.
        Ideal para integraciones con SIEM u otras herramientas automáticas.
        """
        data = {
            "metadata": {
                "timestamp": cls._get_timestamp(),
                "network_cidr": network_cidr,
                "scan_method": scan_method,
                "scan_duration_sec": round(duration, 2),
                "total_devices": len(devices),
            },
            "devices": devices,
        }

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"Error exportando a JSON: {e}")
            return False

    @classmethod
    def to_markdown(
        cls,
        filepath: str,
        devices: List[Dict],
        network_cidr: str,
        scan_method: str = "ARP",
        duration: float = 0.0,
    ) -> bool:
        """
        Exporta los resultados a un documento Markdown renderizable.
        Ideal para reportes de humanos.
        """
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write("# Auditoría de Red Argos — Reporte de Descubrimiento\n\n")

                f.write("## 1. Resumen de Ejecución\n")
                f.write(f"- **Fecha**: `{cls._get_timestamp()}`\n")
                f.write(f"- **Red**: `{network_cidr}`\n")
                f.write(f"- **Método**: `{scan_method}`\n")
                f.write(f"- **Duración**: `{duration:.2f} s`\n")
                f.write(f"- **Dispositivos Totales**: `{len(devices)}`\n\n")

                f.write("## 2. Inventario de Activos\n\n")
                f.write("| # | IP | MAC | Hostname | Latencia (ms) | Fabricante |\n")
                f.write("| :--- | :--- | :--- | :--- | :--- | :--- |\n")

                for i, d in enumerate(devices, 1):
                    ip = d.get("ip", "")
                    mac = d.get("mac", "N/A")
                    host = d.get("hostname", "Desconocido")
                    lat = d.get("latency_ms", "N/A")
                    if lat != "N/A" and isinstance(lat, float):
                        lat = f"{lat:.1f}"
                    vendor = d.get("vendor", "")
                    f.write(f"| {i} | `{ip}` | `{mac}` | {host} | {lat} | {vendor} |\n")

                f.write("\n---\n*Reporte generado automáticamente por Argos Network Toolkit*\n")

            return True
        except Exception as e:
            print(f"Error exportando a Markdown: {e}")
            return False

    @classmethod
    def to_csv(
        cls,
        filepath: str,
        devices: List[Dict],
    ) -> bool:
        """
        Exporta los resultados a un archivo CSV estándar.
        Ideal para abrirlo con Excel o bases de datos relacionales simples.
        """
        if not devices:
            return False

        try:
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                # Establecer los headers
                headers = ["ip", "mac", "hostname", "vendor", "latency_ms", "method"]
                writer.writerow([h.upper() for h in headers])

                for d in devices:
                    row = [
                        d.get("ip", ""),
                        d.get("mac", "N/A"),
                        d.get("hostname", "Desconocido"),
                        d.get("vendor", ""),
                        d.get("latency_ms", ""),
                        d.get("method", ""),
                    ]
                    writer.writerow(row)

            return True
        except Exception as e:
            print(f"Error exportando a CSV: {e}")
            return False
