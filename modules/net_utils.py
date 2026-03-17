"""
NetScanner - Utilidades de Red
Funciones auxiliares para obtener información de interfaces de red,
calcular subredes y validar direcciones IP privadas.
"""

import socket
import ipaddress
import psutil
from typing import List, Dict, Optional, Tuple


def get_local_interfaces() -> List[Dict]:
    """
    Obtiene todas las interfaces de red activas del sistema con su información.
    
    Returns:
        Lista de diccionarios con info de cada interfaz:
        - name: Nombre de la interfaz
        - ip: Dirección IPv4
        - mask: Máscara de subred
        - mac: Dirección MAC
        - type: Tipo estimado (Ethernet/Wi-Fi/Loopback/Virtual)
        - is_up: Si la interfaz está activa
    """
    interfaces = []
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()

    for iface_name, iface_addrs in addrs.items():
        ipv4 = None
        mask = None
        mac = None

        for addr in iface_addrs:
            # IPv4
            if addr.family == socket.AF_INET:
                ipv4 = addr.address
                mask = addr.netmask
            # MAC
            if addr.family == psutil.AF_LINK:
                mac = addr.address

        if ipv4 is None:
            continue

        is_up = stats.get(iface_name, None)
        is_up = is_up.isup if is_up else False

        iface_type = _detect_interface_type(iface_name, ipv4)

        interfaces.append({
            "name": iface_name,
            "ip": ipv4,
            "mask": mask or "255.255.255.0",
            "mac": mac or "N/A",
            "type": iface_type,
            "is_up": is_up,
        })

    return interfaces


def _detect_interface_type(name: str, ip: str) -> str:
    """Detecta el tipo de interfaz basándose en el nombre y la IP."""
    name_lower = name.lower()

    if ip == "127.0.0.1":
        return "🔁 Loopback"
    elif any(kw in name_lower for kw in ["wi-fi", "wifi", "wlan", "wireless"]):
        return "📶 Wi-Fi"
    elif any(kw in name_lower for kw in ["ethernet", "eth", "en0", "enp", "eno"]):
        return "🔌 Ethernet"
    elif any(kw in name_lower for kw in ["vmware", "virtualbox", "vbox", "hyper-v", "docker", "vethernet"]):
        return "💻 Virtual"
    elif any(kw in name_lower for kw in ["vpn", "tun", "tap", "wg"]):
        return "🔒 VPN"
    else:
        return "🌐 Otro"


def get_network_cidr(ip: str, mask: str) -> str:
    """
    Calcula el CIDR de la subred a partir de IP y máscara.
    
    Args:
        ip: Dirección IPv4 (ej: '192.168.1.100')
        mask: Máscara de subred (ej: '255.255.255.0')
    
    Returns:
        String con la red en formato CIDR (ej: '192.168.1.0/24')
    """
    try:
        network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
        return str(network)
    except (ValueError, TypeError):
        return f"{ip}/24"


def is_private_ip(ip: str) -> bool:
    """
    Verifica que una dirección IP sea privada (RFC 1918).
    Esto garantiza que nunca se sale a Internet.
    
    Args:
        ip: Dirección IPv4
    
    Returns:
        True si la IP es privada
    """
    try:
        return ipaddress.IPv4Address(ip).is_private
    except (ValueError, TypeError):
        return False


def resolve_hostname(ip: str, timeout: float = 1.0) -> str:
    """
    Intenta resolver el hostname de una IP mediante DNS inverso.
    
    Args:
        ip: Dirección IPv4
        timeout: Tiempo máximo de espera en segundos
    
    Returns:
        Hostname resuelto o 'Desconocido'
    """
    try:
        socket.setdefaulttimeout(timeout)
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return "Desconocido"


def get_active_interfaces() -> List[Dict]:
    """
    Obtiene solo las interfaces activas con IP privada (excluyendo loopback y virtuales).
    Ideal para seleccionar la interfaz de escaneo.
    """
    interfaces = get_local_interfaces()
    active = []
    for iface in interfaces:
        if (iface["is_up"]
                and iface["ip"] != "127.0.0.1"
                and is_private_ip(iface["ip"])
                and "Virtual" not in iface["type"]
                and "VPN" not in iface["type"]
                and "Loopback" not in iface["type"]):
            active.append(iface)
    return active


def get_gateway_ip(ip: str, mask: str) -> str:
    """
    Estima la IP del gateway (normalmente .1 de la subred).
    
    Args:
        ip: Dirección IPv4 del host
        mask: Máscara de subred
    
    Returns:
        IP estimada del gateway
    """
    try:
        network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
        hosts = list(network.hosts())
        return str(hosts[0]) if hosts else ip
    except (ValueError, TypeError):
        parts = ip.split(".")
        parts[-1] = "1"
        return ".".join(parts)


def get_all_host_ips(ip: str, mask: str) -> List[str]:
    """
    Genera la lista de todas las IPs de host posibles en la subred.
    
    Args:
        ip: Dirección IPv4
        mask: Máscara de subred
    
    Returns:
        Lista de IPs como strings
    """
    try:
        network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
        return [str(h) for h in network.hosts()]
    except (ValueError, TypeError):
        return []
