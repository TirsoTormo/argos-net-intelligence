# pylint: disable=broad-exception-caught, too-many-locals, too-many-branches, too-many-statements, too-few-public-methods
"""
NetScanner - Módulo de Test de Velocidad LAN
Mide la velocidad de transferencia entre dos equipos de la red local
usando comunicación TCP directa (sin salir a Internet).

Modo Servidor: Recibe datos y reporta throughput.
Modo Cliente: Envía datos al servidor y mide velocidad en Mbps.
"""

import socket
import time
import struct
import threading
import json
from typing import Dict, Optional, Callable

from modules.net_utils import is_private_ip

# Protocolo de comunicación
HEADER_SIZE = 8  # 8 bytes para el header (tamaño del mensaje)
DEFAULT_PORT = 45678  # Puerto por defecto del servidor
BLOCK_SIZE = 65536  # 64 KB por bloque de transmisión
DEFAULT_DURATION = 10  # Duración por defecto del test en segundos
BUFFER_SIZE = 131072  # 128 KB buffer de recepción

# Mensajes de control
MSG_START = b"START___"
MSG_DONE = b"DONE____"
MSG_RESULT = b"RESULT__"


class SpeedTestServer:
    """
    Servidor TCP para recibir datos del cliente y medir throughput.
    Se ejecuta en un hilo separado.
    """

    def __init__(self, port: int = DEFAULT_PORT, status_callback: Optional[Callable] = None):
        self.port = port
        self.status_callback = status_callback
        self.server_socket = None
        self.running = False
        self._thread = None
        self.last_result = None

    def _log(self, msg: str):
        if self.status_callback:
            self.status_callback(msg)

    def start(self):
        """Inicia el servidor en un hilo separado."""
        self.running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        """Loop principal del servidor."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Buffer grande para máximo rendimiento
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, BUFFER_SIZE * 4)
            self.server_socket.settimeout(1.0)  # Timeout para permitir parada limpia
            self.server_socket.bind(("0.0.0.0", self.port))
            self.server_socket.listen(1)

            self._log(f"Servidor escuchando en puerto {self.port}...")
            self._log("Esperando conexión del cliente...")

            while self.running:
                try:
                    client_socket, client_addr = self.server_socket.accept()
                    self._log(f"Cliente conectado: {client_addr[0]}:{client_addr[1]}")
                    self._handle_client(client_socket, client_addr)
                except socket.timeout:
                    continue
                except OSError:
                    break

        except OSError as e:
            self._log(f"Error del servidor: {e}")
        finally:
            self._cleanup()

    def _handle_client(self, client_socket: socket.socket, client_addr: tuple):
        """Maneja una conexión de cliente y mide el throughput."""
        try:
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, BUFFER_SIZE * 4)

            # Esperar señal de inicio
            start_msg = client_socket.recv(8)
            if start_msg != MSG_START:
                self._log("Mensaje de inicio inválido")
                return

            self._log("Test de velocidad iniciado — recibiendo datos...")

            total_bytes = 0
            start_time = time.perf_counter()

            while True:
                data = client_socket.recv(BUFFER_SIZE)
                if not data:
                    break

                # Verificar señal de fin
                if data[-8:] == MSG_DONE:
                    total_bytes += len(data) - 8
                    break

                total_bytes += len(data)

            elapsed = time.perf_counter() - start_time

            # Calcular resultados
            speed_mbps = (total_bytes * 8) / (elapsed * 1_000_000) if elapsed > 0 else 0
            speed_mbs = total_bytes / (elapsed * 1_000_000) if elapsed > 0 else 0

            result = {
                "total_bytes": total_bytes,
                "duration_s": round(elapsed, 3),
                "speed_mbps": round(speed_mbps, 2),
                "speed_mbs": round(speed_mbs, 2),
                "client_ip": client_addr[0],
            }

            self.last_result = result

            # Enviar resultado al cliente
            result_json = json.dumps(result).encode("utf-8")
            client_socket.sendall(MSG_RESULT + struct.pack("!I", len(result_json)) + result_json)

            self._log(f"Test completado: {speed_mbps:.2f} Mbps ({speed_mbs:.2f} MB/s)")

        except Exception as e:
            self._log(f"Error manejando cliente: {e}")
        finally:
            client_socket.close()

    def stop(self):
        """Detiene el servidor."""
        self.running = False
        if self._thread:
            self._thread.join(timeout=3)
        self._cleanup()

    def _cleanup(self):
        """Cierra el socket del servidor."""
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
            self.server_socket = None


class SpeedTestClient:
    """
    Cliente TCP para enviar datos al servidor y medir throughput.
    """

    def __init__(self, status_callback: Optional[Callable] = None):
        self.status_callback = status_callback

    def _log(self, msg: str):
        if self.status_callback:
            self.status_callback(msg)

    def run_test(
        self,
        server_ip: str,
        port: int = DEFAULT_PORT,
        duration: int = DEFAULT_DURATION,
        progress_callback: Optional[Callable] = None,
    ) -> Optional[Dict]:
        """
        Ejecuta un test de velocidad contra el servidor.

        Args:
            server_ip: IP del servidor
            port: Puerto del servidor
            duration: Duración del test en segundos
            progress_callback: Callback (msg, percentage)

        Returns:
            Diccionario con resultados o None si falla
        """
        # Verificar que es IP privada (seguridad: nunca salir a Internet)
        if not is_private_ip(server_ip):
            self._log(f"ERROR: {server_ip} no es una IP privada. Operación abortada.")
            return None

        sock = None
        try:
            self._log(f"Conectando a {server_ip}:{port}...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, BUFFER_SIZE * 4)
            sock.settimeout(10)
            sock.connect((server_ip, port))

            self._log("Conexión establecida")

            # Enviar señal de inicio
            sock.sendall(MSG_START)

            # Generar bloque de datos aleatorios
            data_block = b"\x00" * BLOCK_SIZE

            self._log(f"Enviando datos durante {duration} segundos...")

            total_bytes = 0
            start_time = time.perf_counter()
            last_report = start_time

            while True:
                elapsed = time.perf_counter() - start_time
                if elapsed >= duration:
                    break

                try:
                    sock.sendall(data_block)
                    total_bytes += BLOCK_SIZE
                except (BrokenPipeError, ConnectionResetError):
                    break

                # Reportar progreso cada 0.5 segundos
                now = time.perf_counter()
                if now - last_report >= 0.5:
                    pct = elapsed / duration
                    current_speed = (total_bytes * 8) / (elapsed * 1_000_000)
                    if progress_callback:
                        progress_callback(
                            f"Velocidad actual: {current_speed:.1f} Mbps", min(pct, 0.99)
                        )
                    last_report = now

            # Enviar señal de fin
            sock.sendall(MSG_DONE)

            total_elapsed = time.perf_counter() - start_time

            # Calcular resultados del lado del cliente
            client_speed_mbps = (
                (total_bytes * 8) / (total_elapsed * 1_000_000) if total_elapsed > 0 else 0
            )
            client_speed_mbs = total_bytes / (total_elapsed * 1_000_000) if total_elapsed > 0 else 0

            # Intentar recibir resultados del servidor
            server_result = None
            try:
                sock.settimeout(5)
                header = sock.recv(12)  # MSG_RESULT (8) + length (4)
                if header[:8] == MSG_RESULT:
                    result_len = struct.unpack("!I", header[8:12])[0]
                    result_data = b""
                    while len(result_data) < result_len:
                        chunk = sock.recv(result_len - len(result_data))
                        if not chunk:
                            break
                        result_data += chunk
                    server_result = json.loads(result_data.decode("utf-8"))
            except Exception:
                pass

            result = {
                "server_ip": server_ip,
                "port": port,
                "duration_s": round(total_elapsed, 3),
                "total_bytes": total_bytes,
                "total_MB": round(total_bytes / (1024 * 1024), 2),
                "client_speed_mbps": round(client_speed_mbps, 2),
                "client_speed_mbs": round(client_speed_mbs, 2),
            }

            if server_result:
                result["server_speed_mbps"] = server_result.get("speed_mbps", 0)
                result["server_speed_mbs"] = server_result.get("speed_mbs", 0)

            if progress_callback:
                progress_callback("Test completado", 1.0)

            self._log(
                f"Test completado: {client_speed_mbps:.2f} Mbps ({client_speed_mbs:.2f} MB/s)"
            )
            return result

        except socket.timeout:
            self._log(f"Timeout: No se pudo conectar a {server_ip}:{port}")
            return None
        except ConnectionRefusedError:
            self._log(f"Conexión rechazada: ¿Está el servidor ejecutándose en {server_ip}:{port}?")
            return None
        except Exception as e:
            self._log(f"Error: {e}")
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass


def quick_latency_test(target_ip: str, count: int = 5) -> Optional[Dict]:
    """
    Test rápido de latencia TCP contra un host.
    Abre y cierra conexiones para medir RTT.

    Args:
        target_ip: IP destino
        count: Número de intentos

    Returns:
        Diccionario con min/avg/max/jitter en ms
    """
    if not is_private_ip(target_ip):
        return None

    latencies = []
    port = DEFAULT_PORT

    for _ in range(count):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)

        start = time.perf_counter()
        try:
            sock.connect((target_ip, port))
            elapsed = (time.perf_counter() - start) * 1000
            latencies.append(elapsed)
            sock.close()
        except Exception:
            sock.close()

    if not latencies:
        return None

    avg = sum(latencies) / len(latencies)
    jitter = max(latencies) - min(latencies) if len(latencies) > 1 else 0

    return {
        "min_ms": round(min(latencies), 2),
        "avg_ms": round(avg, 2),
        "max_ms": round(max(latencies), 2),
        "jitter_ms": round(jitter, 2),
        "samples": len(latencies),
    }
