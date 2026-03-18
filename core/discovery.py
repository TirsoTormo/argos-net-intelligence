# pylint: disable=too-many-locals, broad-exception-caught, import-outside-toplevel, unused-variable, subprocess-run-check, unused-import
"""
NetScanner - Módulo de Descubrimiento de Red
Escanea la red local para detectar dispositivos conectados.
Usa ARP Scan (Scapy) como método principal y Ping Sweep como fallback.
"""

import subprocess
import platform
import time
import re
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Callable

from core.net_utils import (
    get_network_cidr,
    get_all_host_ips,
    resolve_hostname,
    is_private_ip,
)


def arp_scan(ip: str, mask: str, progress_callback: Optional[Callable] = None) -> List[Dict]:
    """
    Escaneo ARP usando Scapy. Método rápido y preciso.
    Requiere privilegios de administrador.

    Args:
        ip: IP local del host
        mask: Máscara de subred
        progress_callback: Función opcional para reportar progreso

    Returns:
        Lista de dispositivos descubiertos
    """
    try:
        from scapy.all import ARP, Ether, srp, conf

        conf.verb = 0  # Silenciar output de Scapy

        cidr = get_network_cidr(ip, mask)

        if progress_callback:
            progress_callback("Enviando paquetes ARP...", 0.1)

        arp_request = ARP(pdst=cidr)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request

        if progress_callback:
            progress_callback("Esperando respuestas...", 0.3)

        answered, _ = srp(packet, timeout=3, retry=1, verbose=False)

        devices = []
        total = len(answered)

        for i, (sent, received) in enumerate(answered):
            target_ip = received.psrc
            target_mac = received.hwsrc

            if target_ip == ip:
                continue

            if progress_callback:
                pct = 0.4 + (0.5 * (i + 1) / max(total, 1))
                progress_callback(f"Resolviendo {target_ip}...", pct)

            hostname = resolve_hostname(target_ip)
            latency = _ping_host(target_ip)

            devices.append(
                {
                    "ip": target_ip,
                    "mac": target_mac.upper(),
                    "hostname": hostname,
                    "latency_ms": latency,
                    "vendor": "",
                    "method": "ARP",
                }
            )

        if progress_callback:
            progress_callback("Escaneo ARP completado", 1.0)

        devices.sort(key=lambda d: ipaddress.IPv4Address(d["ip"]))
        return devices

    except ImportError:
        return []
    except PermissionError:
        return []
    except Exception:
        return []


def ping_sweep(
    ip: str, mask: str, max_workers: int = 50, progress_callback: Optional[Callable] = None
) -> List[Dict]:
    """
    Escaneo por Ping Sweep usando el comando 'ping' nativo del sistema.
    Método de fallback que no requiere privilegios especiales.

    Args:
        ip: IP local del host
        mask: Máscara de subred
        max_workers: Número máximo de hilos concurrentes
        progress_callback: Función opcional para reportar progreso

    Returns:
        Lista de dispositivos descubiertos
    """
    host_ips = get_all_host_ips(ip, mask)
    # Excluir nuestra propia IP
    host_ips = [h for h in host_ips if h != ip]

    if not host_ips:
        return []

    devices = []
    total = len(host_ips)
    completed = 0

    def ping_single(target_ip: str) -> Optional[Dict]:
        nonlocal completed
        latency = _ping_host(target_ip)
        completed += 1

        if progress_callback and completed % 10 == 0:
            pct = completed / total
            progress_callback(f"Ping {completed}/{total} - {target_ip}", pct)

        if latency is not None:
            hostname = resolve_hostname(target_ip)
            mac = _get_mac_from_arp_table(target_ip)
            return {
                "ip": target_ip,
                "mac": mac,
                "hostname": hostname,
                "latency_ms": latency,
                "vendor": "",
                "method": "Ping",
            }
        return None

    if progress_callback:
        progress_callback(f"Iniciando ping sweep en {total} hosts...", 0.0)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(ping_single, h): h for h in host_ips}
        for future in as_completed(futures):
            result = future.result()
            if result:
                devices.append(result)

    if progress_callback:
        progress_callback("Ping sweep completado", 1.0)

    devices.sort(key=lambda d: ipaddress.IPv4Address(d["ip"]))
    return devices


def full_scan(ip: str, mask: str, progress_callback: Optional[Callable] = None) -> tuple:
    """
    Ejecuta un escaneo completo: intenta ARP primero, si falla usa Ping Sweep.

    Args:
        ip: IP local del host
        mask: Máscara de subred
        progress_callback: Callback de progreso

    Returns:
        Tupla (lista_dispositivos, método_usado)
    """
    if progress_callback:
        progress_callback("Intentando escaneo ARP...", 0.0)

    devices = arp_scan(ip, mask, progress_callback)

    if devices:
        return devices, "ARP Scan (Scapy)"

    if progress_callback:
        progress_callback("ARP no disponible, usando Ping Sweep...", 0.05)

    devices = ping_sweep(ip, mask, progress_callback=progress_callback)
    return devices, "Ping Sweep (fallback)"


def _ping_host(ip: str, count: int = 1, timeout: int = 1) -> Optional[float]:
    """
    Hace ping a un host y retorna la latencia en ms.

    Returns:
        Latencia en ms o None si no responde
    """
    system = platform.system().lower()

    if system == "windows":
        cmd = ["ping", "-n", str(count), "-w", str(timeout * 1000), ip]
    else:
        cmd = ["ping", "-c", str(count), "-W", str(timeout), ip]

    try:
        start = time.perf_counter()
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout + 2,
            creationflags=subprocess.CREATE_NO_WINDOW if system == "windows" else 0,
        )
        elapsed = (time.perf_counter() - start) * 1000

        if result.returncode == 0:
            output = result.stdout.decode("utf-8", errors="ignore")
            # Intentar extraer latencia del output
            match = re.search(r"[=<]\s*(\d+(?:\.\d+)?)\s*ms", output)
            if match:
                return float(match.group(1))
            return round(elapsed, 2)
        return None
    except (subprocess.TimeoutExpired, Exception):
        return None


def _get_mac_from_arp_table(ip: str) -> str:
    """
    Busca la MAC de una IP en la tabla ARP del sistema.
    """
    try:
        system = platform.system().lower()
        if system == "windows":
            cmd = ["arp", "-a", ip]
        else:
            cmd = ["arp", "-n", ip]

        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=3,
            creationflags=subprocess.CREATE_NO_WINDOW if system == "windows" else 0,
        )
        output = result.stdout.decode("utf-8", errors="ignore")

        # Buscar MAC en formato xx-xx-xx-xx-xx-xx o xx:xx:xx:xx:xx:xx
        mac_pattern = r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}"
        match = re.search(mac_pattern, output)
        if match:
            return match.group(0).upper().replace("-", ":")
        return "N/A"
    except Exception:
        return "N/A"


