"""
Argos — Packet Factory (Fábrica de Paquetes)
=============================================
Motor de construcción y envío de paquetes de red personalizados
operando en las capas 2 (Enlace), 3 (Red) y 4 (Transporte) del modelo OSI.

Requiere:
    - Scapy instalado
    - Privilegios de administrador
    - Solo redes privadas (RFC 1918)
"""

import time
from typing import Optional, Dict, List, Any, Callable

from modules.net_utils import is_private_ip


# ─────────────────────────────────────────────────────────────
# Verificación de dependencias
# ─────────────────────────────────────────────────────────────

def _require_scapy():
    """Importa Scapy o lanza error descriptivo."""
    try:
        from scapy.all import (
            Ether, ARP, IP, TCP, UDP, ICMP,
            sr1, sr, srp, send, sendp, conf, RandShort
        )
        conf.verb = 0
        return True
    except ImportError:
        raise ImportError(
            "Scapy es requerido para Packet Factory.\n"
            "Instálalo con: pip install scapy"
        )


def _validate_target(ip: str):
    """Valida que el destino sea una IP privada."""
    if not is_private_ip(ip):
        raise ValueError(
            f"BLOQUEADO: {ip} no es una IP privada (RFC 1918).\n"
            f"Argos solo opera dentro de la red local."
        )


# ─────────────────────────────────────────────────────────────
# CAPA 2 — Enlace de datos (Ethernet / ARP)
# ─────────────────────────────────────────────────────────────

def craft_ethernet_frame(dst_mac: str, src_mac: str, 
                         ether_type: int = 0x0800) -> Any:
    """
    Construye una trama Ethernet con MACs personalizadas.
    
    Args:
        dst_mac: MAC destino (ej: 'ff:ff:ff:ff:ff:ff')
        src_mac: MAC origen personalizada
        ether_type: Tipo Ethernet (0x0800=IPv4, 0x0806=ARP)
    
    Returns:
        Objeto Ether de Scapy
    """
    _require_scapy()
    from scapy.all import Ether
    
    frame = Ether(dst=dst_mac, src=src_mac, type=ether_type)
    return frame


def send_arp_request(target_ip: str, src_ip: Optional[str] = None,
                     src_mac: Optional[str] = None,
                     timeout: int = 2,
                     log_callback: Optional[Callable] = None) -> Optional[Dict]:
    """
    Envía un ARP Request personalizado y espera respuesta.
    
    Args:
        target_ip: IP destino del ARP request
        src_ip: IP origen (por defecto la de la interfaz activa)
        src_mac: MAC origen personalizada (opcional)
        timeout: Timeout en segundos
        log_callback: Callback para log de operaciones
    
    Returns:
        Diccionario con la respuesta ARP o None
    """
    _require_scapy()
    _validate_target(target_ip)
    from scapy.all import Ether, ARP, srp

    def _log(msg):
        if log_callback:
            log_callback(msg)

    _log(f"[CAPA 2] Enviando ARP Request → {target_ip}")

    ether_kwargs = {"dst": "ff:ff:ff:ff:ff:ff"}
    if src_mac:
        ether_kwargs["src"] = src_mac

    arp_kwargs = {"pdst": target_ip}
    if src_ip:
        arp_kwargs["psrc"] = src_ip

    packet = Ether(**ether_kwargs) / ARP(**arp_kwargs)

    _log(f"[CAPA 2] Paquete: {packet.summary()}")

    answered, _ = srp(packet, timeout=timeout, verbose=False)

    if answered:
        _, reply = answered[0]
        result = {
            "target_ip": target_ip,
            "response_ip": reply.psrc,
            "response_mac": reply.hwsrc.upper(),
            "operation": "ARP Reply",
        }
        _log(f"[CAPA 2] Respuesta: {reply.hwsrc.upper()} → {reply.psrc}")
        return result
    
    _log(f"[CAPA 2] Sin respuesta de {target_ip}")
    return None


def arp_table_scan(network_cidr: str, 
                   log_callback: Optional[Callable] = None) -> List[Dict]:
    """
    Escaneo ARP completo de una subred para poblar la tabla ARP.
    
    Args:
        network_cidr: Red en formato CIDR (ej: '192.168.1.0/24')
        log_callback: Callback para logs
    
    Returns:
        Lista de dispositivos con IP y MAC
    """
    _require_scapy()
    from scapy.all import Ether, ARP, srp

    def _log(msg):
        if log_callback:
            log_callback(msg)

    _log(f"[CAPA 2] ARP scan en {network_cidr}")

    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network_cidr)
    answered, _ = srp(packet, timeout=3, verbose=False)

    devices = []
    for sent, received in answered:
        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc.upper(),
        })

    _log(f"[CAPA 2] {len(devices)} dispositivos detectados")
    return devices


# ─────────────────────────────────────────────────────────────
# CAPA 3 — Red (IP / ICMP)
# ─────────────────────────────────────────────────────────────

def craft_ip_packet(dst_ip: str, src_ip: Optional[str] = None,
                    ttl: int = 64, tos: int = 0, 
                    flags: int = 0, frag: int = 0,
                    id: Optional[int] = None) -> Any:
    """
    Construye un paquete IP con parámetros personalizados.
    
    Args:
        dst_ip: IP destino
        src_ip: IP origen personalizada (spoofing local)
        ttl: Time To Live (1-255)
        tos: Type of Service / DSCP
        flags: IP flags (0=none, 1=MF, 2=DF, 3=MF+DF)
        frag: Fragment offset
        id: ID del paquete IP
    
    Returns:
        Objeto IP de Scapy
    """
    _require_scapy()
    _validate_target(dst_ip)
    from scapy.all import IP

    kwargs = {"dst": dst_ip, "ttl": ttl, "tos": tos, "flags": flags, "frag": frag}
    if src_ip:
        kwargs["src"] = src_ip
    if id is not None:
        kwargs["id"] = id

    return IP(**kwargs)


def manual_traceroute(dst_ip: str, max_hops: int = 30, timeout: int = 2,
                      log_callback: Optional[Callable] = None) -> List[Dict]:
    """
    Traceroute manual usando paquetes ICMP con TTL incremental.
    Solo funciona con IPs privadas o locales.
    
    Args:
        dst_ip: IP destino
        max_hops: Máximo de saltos
        timeout: Timeout por salto
        log_callback: Callback de log
    
    Returns:
        Lista de saltos con TTL, IP y latencia
    """
    _require_scapy()
    _validate_target(dst_ip)
    from scapy.all import IP, ICMP, sr1

    def _log(msg):
        if log_callback:
            log_callback(msg)

    _log(f"[CAPA 3] Traceroute manual → {dst_ip} (max {max_hops} saltos)")

    hops = []
    for ttl in range(1, max_hops + 1):
        pkt = IP(dst=dst_ip, ttl=ttl) / ICMP()
        
        start = time.perf_counter()
        reply = sr1(pkt, timeout=timeout, verbose=False)
        elapsed = (time.perf_counter() - start) * 1000

        if reply is None:
            hop = {"ttl": ttl, "ip": "*", "latency_ms": None, "status": "timeout"}
            _log(f"  TTL {ttl:>2d}: * (timeout)")
        else:
            hop_ip = reply.src
            hop = {"ttl": ttl, "ip": hop_ip, "latency_ms": round(elapsed, 2), "status": "ok"}
            _log(f"  TTL {ttl:>2d}: {hop_ip} ({elapsed:.1f} ms)")

            # Si llegamos al destino, parar
            if hop_ip == dst_ip:
                hops.append(hop)
                break

        hops.append(hop)

    _log(f"[CAPA 3] Traceroute completado: {len(hops)} saltos")
    return hops


def send_icmp_ping(dst_ip: str, count: int = 4, ttl: int = 64,
                   payload_size: int = 56,
                   log_callback: Optional[Callable] = None) -> Dict:
    """
    Ping ICMP personalizado con control total de parámetros.
    
    Args:
        dst_ip: IP destino
        count: Número de pings
        ttl: TTL del paquete
        payload_size: Tamaño del payload en bytes
        log_callback: Callback de log
    
    Returns:
        Estadísticas de ping (min/avg/max/loss)
    """
    _require_scapy()
    _validate_target(dst_ip)
    from scapy.all import IP, ICMP, Raw, sr1

    def _log(msg):
        if log_callback:
            log_callback(msg)

    _log(f"[CAPA 3] ICMP Ping → {dst_ip} (count={count}, ttl={ttl}, size={payload_size})")

    payload = Raw(load=b"\x00" * payload_size)
    latencies = []
    lost = 0

    for seq in range(count):
        pkt = IP(dst=dst_ip, ttl=ttl) / ICMP(seq=seq) / payload
        
        start = time.perf_counter()
        reply = sr1(pkt, timeout=2, verbose=False)
        elapsed = (time.perf_counter() - start) * 1000

        if reply and reply.haslayer(ICMP):
            latencies.append(elapsed)
            _log(f"  #{seq+1}: {elapsed:.1f} ms (ttl={reply[IP].ttl})")
        else:
            lost += 1
            _log(f"  #{seq+1}: * (timeout)")

    stats = {
        "dst": dst_ip,
        "sent": count,
        "received": count - lost,
        "lost": lost,
        "loss_pct": round((lost / count) * 100, 1),
        "min_ms": round(min(latencies), 2) if latencies else None,
        "avg_ms": round(sum(latencies) / len(latencies), 2) if latencies else None,
        "max_ms": round(max(latencies), 2) if latencies else None,
    }

    _log(f"[CAPA 3] Resultado: {stats['received']}/{stats['sent']} recibidos, "
         f"pérdida {stats['loss_pct']}%")
    return stats


# ─────────────────────────────────────────────────────────────
# CAPA 4 — Transporte (TCP / UDP)
# ─────────────────────────────────────────────────────────────

# Mapa de flags TCP para referencia
TCP_FLAGS = {
    "F": "FIN",
    "S": "SYN",
    "R": "RST",
    "P": "PSH",
    "A": "ACK",
    "U": "URG",
    "E": "ECE",
    "C": "CWR",
}


def craft_tcp_segment(dst_ip: str, dst_port: int,
                      flags: str = "S",
                      src_port: Optional[int] = None,
                      src_ip: Optional[str] = None,
                      seq: int = 0, ack: int = 0,
                      window: int = 8192,
                      ttl: int = 64) -> Any:
    """
    Construye un segmento TCP con flags personalizados.
    
    Args:
        dst_ip: IP destino
        dst_port: Puerto destino
        flags: Flags TCP como string (ej: 'S' = SYN, 'SA' = SYN+ACK, 'FA' = FIN+ACK)
               Flags válidos: S(YN), A(CK), F(IN), R(ST), P(SH), U(RG), E(CE), C(WR)
        src_port: Puerto origen (aleatorio si no se especifica)
        src_ip: IP origen personalizada
        seq: Sequence number
        ack: Acknowledgment number
        window: Window size
        ttl: TTL del paquete IP
    
    Returns:
        Objeto IP/TCP de Scapy
    """
    _require_scapy()
    _validate_target(dst_ip)
    from scapy.all import IP, TCP, RandShort

    ip_kwargs = {"dst": dst_ip, "ttl": ttl}
    if src_ip:
        ip_kwargs["src"] = src_ip

    tcp_kwargs = {
        "dport": dst_port,
        "sport": src_port or int(RandShort()),
        "flags": flags,
        "seq": seq,
        "ack": ack,
        "window": window,
    }

    return IP(**ip_kwargs) / TCP(**tcp_kwargs)


def tcp_port_probe(dst_ip: str, ports: List[int],
                   timeout: int = 2,
                   log_callback: Optional[Callable] = None) -> List[Dict]:
    """
    Sondeo TCP SYN a puertos específicos para detectar servicios.
    Envía SYN y analiza la respuesta (SYN-ACK = abierto, RST = cerrado).
    
    Args:
        dst_ip: IP destino
        ports: Lista de puertos a sondear
        timeout: Timeout por puerto
        log_callback: Callback de log
    
    Returns:
        Lista de resultados por puerto
    """
    _require_scapy()
    _validate_target(dst_ip)
    from scapy.all import IP, TCP, sr1, RandShort

    def _log(msg):
        if log_callback:
            log_callback(msg)

    _log(f"[CAPA 4] TCP SYN probe → {dst_ip} ({len(ports)} puertos)")

    results = []
    for port in ports:
        pkt = IP(dst=dst_ip) / TCP(dport=port, sport=int(RandShort()), flags="S")
        
        reply = sr1(pkt, timeout=timeout, verbose=False)
        
        if reply is None:
            status = "filtered"
            flag_str = "-"
        elif reply.haslayer(TCP):
            reply_flags = reply[TCP].flags
            flag_str = str(reply_flags)
            if reply_flags & 0x12 == 0x12:  # SYN+ACK
                status = "open"
            elif reply_flags & 0x04:  # RST
                status = "closed"
            else:
                status = "unknown"
        else:
            status = "unknown"
            flag_str = "-"

        result = {
            "port": port,
            "status": status,
            "flags_received": flag_str,
            "service": _common_service(port),
        }
        results.append(result)

        icon = {"open": "🟢", "closed": "🔴", "filtered": "🟡"}.get(status, "⚪")
        _log(f"  {icon} Puerto {port:>5d}/{_common_service(port):<10s}: "
             f"{status.upper()} (flags: {flag_str})")

    return results


def send_tcp_custom(dst_ip: str, dst_port: int, flags: str = "S",
                    src_port: Optional[int] = None,
                    payload: Optional[bytes] = None,
                    timeout: int = 3,
                    log_callback: Optional[Callable] = None) -> Optional[Dict]:
    """
    Envía un segmento TCP totalmente personalizado y captura la respuesta.
    
    Args:
        dst_ip: IP destino
        dst_port: Puerto destino
        flags: Flags TCP (ej: 'S', 'SA', 'FA', 'R', 'PA')
        src_port: Puerto origen
        payload: Datos a incluir en el segmento
        timeout: Timeout de espera
        log_callback: Callback de log
    
    Returns:
        Diccionario con detalles de la respuesta
    """
    _require_scapy()
    _validate_target(dst_ip)
    from scapy.all import IP, TCP, Raw, sr1, RandShort

    def _log(msg):
        if log_callback:
            log_callback(msg)

    sport = src_port or int(RandShort())
    
    _log(f"[CAPA 4] TCP {flags} → {dst_ip}:{dst_port} (src_port={sport})")
    _log(f"         Flags: {' + '.join(TCP_FLAGS.get(f, f) for f in flags)}")

    pkt = IP(dst=dst_ip) / TCP(dport=dst_port, sport=sport, flags=flags)
    
    if payload:
        pkt = pkt / Raw(load=payload)
        _log(f"         Payload: {len(payload)} bytes")

    start = time.perf_counter()
    reply = sr1(pkt, timeout=timeout, verbose=False)
    elapsed = (time.perf_counter() - start) * 1000

    if reply is None:
        _log(f"[CAPA 4] Sin respuesta (timeout {timeout}s)")
        return {"status": "no_response", "latency_ms": None}

    result = {
        "status": "response",
        "latency_ms": round(elapsed, 2),
        "src_ip": reply.src,
    }

    if reply.haslayer(TCP):
        tcp_layer = reply[TCP]
        result.update({
            "flags_received": str(tcp_layer.flags),
            "src_port": tcp_layer.sport,
            "dst_port": tcp_layer.dport,
            "seq": tcp_layer.seq,
            "ack": tcp_layer.ack,
            "window": tcp_layer.window,
        })
        _log(f"[CAPA 4] Respuesta: flags={tcp_layer.flags} seq={tcp_layer.seq} "
             f"ack={tcp_layer.ack} win={tcp_layer.window} ({elapsed:.1f} ms)")

    return result


def craft_udp_datagram(dst_ip: str, dst_port: int,
                       src_port: Optional[int] = None,
                       payload: Optional[bytes] = None,
                       ttl: int = 64) -> Any:
    """
    Construye un datagrama UDP personalizado.
    
    Args:
        dst_ip: IP destino
        dst_port: Puerto destino
        src_port: Puerto origen
        payload: Datos UDP
        ttl: TTL del paquete IP
    
    Returns:
        Objeto IP/UDP de Scapy
    """
    _require_scapy()
    _validate_target(dst_ip)
    from scapy.all import IP, UDP, Raw, RandShort

    pkt = IP(dst=dst_ip, ttl=ttl) / UDP(
        dport=dst_port,
        sport=src_port or int(RandShort())
    )

    if payload:
        pkt = pkt / Raw(load=payload)

    return pkt


def send_udp_probe(dst_ip: str, dst_port: int,
                   payload: Optional[bytes] = None,
                   timeout: int = 3,
                   log_callback: Optional[Callable] = None) -> Dict:
    """
    Envía un datagrama UDP y analiza la respuesta.
    UDP es "fire and forget", pero puede recibir ICMP Port Unreachable.
    
    Args:
        dst_ip: IP destino
        dst_port: Puerto destino
        payload: Datos a enviar
        timeout: Timeout
        log_callback: Callback de log
    
    Returns:
        Resultado del sondeo
    """
    _require_scapy()
    _validate_target(dst_ip)
    from scapy.all import IP, UDP, ICMP, Raw, sr1, RandShort

    def _log(msg):
        if log_callback:
            log_callback(msg)

    _log(f"[CAPA 4] UDP probe → {dst_ip}:{dst_port}")

    pkt = IP(dst=dst_ip) / UDP(dport=dst_port, sport=int(RandShort()))
    if payload:
        pkt = pkt / Raw(load=payload)

    start = time.perf_counter()
    reply = sr1(pkt, timeout=timeout, verbose=False)
    elapsed = (time.perf_counter() - start) * 1000

    if reply is None:
        _log(f"[CAPA 4] Sin respuesta → open|filtered")
        return {"port": dst_port, "status": "open|filtered", "latency_ms": None}

    if reply.haslayer(ICMP):
        icmp_type = reply[ICMP].type
        icmp_code = reply[ICMP].code
        if icmp_type == 3 and icmp_code == 3:
            _log(f"[CAPA 4] ICMP Port Unreachable → closed")
            return {"port": dst_port, "status": "closed", "latency_ms": round(elapsed, 2)}
        else:
            _log(f"[CAPA 4] ICMP type={icmp_type} code={icmp_code} → filtered")
            return {"port": dst_port, "status": "filtered", "latency_ms": round(elapsed, 2)}

    if reply.haslayer(UDP):
        _log(f"[CAPA 4] Respuesta UDP → open")
        return {"port": dst_port, "status": "open", "latency_ms": round(elapsed, 2)}

    return {"port": dst_port, "status": "unknown", "latency_ms": round(elapsed, 2)}


# ─────────────────────────────────────────────────────────────
# Utilidades
# ─────────────────────────────────────────────────────────────

def _common_service(port: int) -> str:
    """Devuelve el nombre del servicio común para un puerto."""
    services = {
        20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet",
        25: "smtp", 53: "dns", 67: "dhcp-s", 68: "dhcp-c",
        69: "tftp", 80: "http", 110: "pop3", 123: "ntp",
        143: "imap", 161: "snmp", 162: "snmptrap",
        443: "https", 445: "smb", 514: "syslog",
        993: "imaps", 995: "pop3s",
        1433: "mssql", 1521: "oracle", 3306: "mysql",
        3389: "rdp", 5432: "pgsql", 5900: "vnc",
        6379: "redis", 8080: "http-alt", 8443: "https-alt",
        8291: "winbox", 8728: "mikrotik-api", 8729: "mikrotik-apis",
        179: "bgp", 520: "rip", 1723: "pptp",
        500: "ike", 4500: "ipsec-nat",
    }
    return services.get(port, "unknown")


def describe_flags(flags: str) -> str:
    """Devuelve una descripción legible de los flags TCP."""
    parts = []
    for char in flags.upper():
        name = TCP_FLAGS.get(char, char)
        parts.append(name)
    return " + ".join(parts) if parts else "None"


def get_common_port_groups() -> Dict[str, List[int]]:
    """Devuelve grupos de puertos comunes para escaneos rápidos."""
    return {
        "web": [80, 443, 8080, 8443],
        "remote": [22, 23, 3389, 5900],
        "database": [1433, 1521, 3306, 5432, 6379],
        "email": [25, 110, 143, 993, 995],
        "dns": [53],
        "file": [20, 21, 69, 445],
        "network": [161, 162, 179, 520, 514],
        "mikrotik": [8291, 8728, 8729, 22, 23, 80, 443],
        "top20": [21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
                  443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443],
    }
