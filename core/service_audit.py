"""
L7 Service Intelligence Module (Argos v1.2.0)
Extrae banners de servicios y metadata de hardware (SNMP) saltándose la capa de transporte.
"""
import socket
from typing import Optional, Callable


def grab_banner(
    dst_ip: str, 
    port: int, 
    timeout: float = 2.0, 
    log_callback: Optional[Callable] = None
) -> str:
    """
    Intenta conectarse al puerto y leer el banner inicial del servicio 
    (ej: servidor SSH, FTP, HTTP, SMTP) para identificar la versión exactas.
    """
    def _log(msg):
        if log_callback:
            log_callback(msg)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((dst_ip, port))
            
            # Application Payload Injection for silent protocols
            if port in [80, 8080]:
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port == 443:
                # SSL Wrap is needed but for raw banner grabbing without SSL context:
                # It's better to just leave it or use a basic TLS client hello
                pass 
            elif port in [21, 22, 25]:
                # FTP, SSH, SMTP usually broadcast strings immediately upon connection
                pass

            # Leer respuesta
            banner_raw = s.recv(1024)
            if not banner_raw:
                return ""
                
            banner = banner_raw.decode('utf-8', errors='ignore').strip()

            if banner:
                lines = [line.strip() for line in banner.split('\n') if line.strip()]
                if port in [80, 8080, 443]:
                    # Extract "Server: Apache/2.4.x" header if present
                    for line in lines:
                        if line.lower().startswith("server:"):
                            return line[7:].strip()[:80]
                
                # Default behavior: return first line
                if lines:
                    return lines[0][:80] # Limit length

    except Exception:
        pass
        
    return ""


def snmp_sysdescr(
    dst_ip: str, 
    community: str = "public", 
    timeout: float = 1.5, 
    log_callback: Optional[Callable] = None
) -> Optional[str]:
    """
    Realiza una consulta SNMP v2c básica para obtener el sysDescr 
    (identificación del sistema, hardware y SO).
    """
    from core.packet_factory import _validate_target
    _validate_target(dst_ip)
    from scapy.all import IP, UDP, sr1
    from scapy.layers.snmp import SNMP, SNMPget, SNMPvarbind, ASN1_OID

    def _log(msg):
        if log_callback:
            log_callback(msg)

    _log(f"[CAPA 7] SNMP sysDescr probe → {dst_ip} (community: '{community}')")

    try:
        # sysDescr.0 OID = 1.3.6.1.2.1.1.1.0
        req = IP(dst=dst_ip) / UDP(sport=10061, dport=161) / \
              SNMP(community=community, version=1, 
                   PDU=SNMPget(varbindlist=[SNMPvarbind(oid=ASN1_OID('1.3.6.1.2.1.1.1.0'))]))
              
        reply = sr1(req, timeout=timeout, verbose=False)
        
        if reply and reply.haslayer(SNMP):
            snmp_layer = reply[SNMP]
            if hasattr(snmp_layer, 'PDU') and hasattr(snmp_layer.PDU, 'varbindlist'):
                for varbind in snmp_layer.PDU.varbindlist:
                    if hasattr(varbind, 'value'):
                        val = varbind.value
                        if hasattr(val, 'val'):
                            desc = val.val.decode('utf-8', errors='ignore')
                            desc = desc.replace('\r', ' ').replace('\n', ' ').strip()
                            _log(f"[CAPA 7] SNMP Respuesta: {desc[:60]}...")
                            return desc
                        elif isinstance(val, bytes):
                            desc = val.decode('utf-8', errors='ignore')
                            _log(f"[CAPA 7] SNMP Respuesta: {desc[:60]}...")
                            return desc
        
        _log("[CAPA 7] Sin respuesta SNMP válida")
    except Exception as e:
        _log(f"[CAPA 7] Error SNMP: {e}")
        
    return None
