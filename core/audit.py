"""
Argos — Security Audit Module
Módulo especializado en auditoría pasiva y activa de configuraciones
críticas de red (Detección de DHCP Rogue, Validación de Certificados SSL).
"""

import socket
import ssl
import time
from typing import Dict, List, Optional, Callable


def ssl_cert_check(dst_ip: str, port: int = 443, timeout: float = 3.0, log_callback: Optional[Callable] = None) -> Dict:
    """
    Obtiene el certificado SSL/TLS de un servicio y valida su expiración
    y parámetros básicos para auditorías de seguridad.
    """
    def _log(msg):
        if log_callback:
            log_callback(msg)

    _log(f"[AUDIT] SSL Check → {dst_ip}:{port}")
    
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # Queremos el certificado, incluso si no confíamos en la CA local

    result = {
        "status": "error",
        "issuer": "N/A",
        "subject": "N/A",
        "expired": False,
        "days_left": 0,
        "version": "N/A"
    }

    try:
        with socket.create_connection((dst_ip, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=dst_ip) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                # Extraemos info con el modulo cryptography si está si no parseamos nativo
                # Usaremos métodos nativos limitados primero.
                # getpeercert sin binary_form solo devuelve info si es validado, así que bajamos a pyOpenSSL
                # o cargamos el der manual. Para no depender de PyOpenSSL:
                return _parse_cert_basic(ssock.getpeercert(), ssock.version())
    except Exception as e:
        _log(f"[AUDIT] Error SSL/TLS: {e}")
        return result


def _parse_cert_basic(cert_dict: Optional[Dict], ssl_version: str) -> Dict:
    """Intenta extraer la info si la validación fue al menos parcial, 
       requiere verify_mode != CERT_NONE pero eso rompe certificados autofirmados.
       Si se usa CERT_NONE ssl.getpeercert() devuelve {} en Python estándar.
       Para solucionarlo usamos un truco con sockets."""
    pass


def ssl_cert_check_advanced(dst_ip: str, port: int = 443, timeout: float = 3.0, log_callback: Optional[Callable] = None) -> Dict:
    """Versión que extrae fechas manualmente usando ssl y sockets."""
    import datetime

    def _log(msg):
        if log_callback:
            log_callback(msg)

    _log(f"[AUDIT] SSL Cert Check → {dst_ip}:{port}")
    
    result = {
        "status": "unknown",
        "issuer": "N/A",
        "subject": "N/A",
        "valid_from": "N/A",
        "valid_to": "N/A",
        "days_left": 0,
        "expired": False,
        "version": "N/A"
    }

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    # Truco: ignorar errores para forzar la carga del cert dict
    
    try:
        # Usamos el modo normal primero
        with socket.create_connection((dst_ip, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=dst_ip) as ssock:
                der = ssock.getpeercert(binary_form=False)
    except ssl.SSLCertVerificationError as e:
        # Aquí falló porque es autofirmado, pero el objeto excepción tiene acceso al certificado
        der = e.verify_message # No siempre útil
    except ssl.SSLError:
        context.verify_mode = ssl.CERT_NONE
        try:
             with socket.create_connection((dst_ip, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=dst_ip) as ssock:
                    der = ssock.getpeercert(binary_form=False) # devuelve dic vacio con CERT_NONE
        except Exception:
            return result
    except Exception as e:
        _log(f"[AUDIT] Socket Error: {e}")
        return result

    # Vamos a usar el modo correcto para Python >= 3.2 que es getpeercert sin binario
    # Requiere que verify_mode = CERT_OPTIONAL
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_OPTIONAL

    try:
        with socket.create_connection((dst_ip, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=dst_ip) as ssock:
                cert = ssock.getpeercert()
                result["version"] = ssock.version()
                result["status"] = "ok"
                
                if cert:
                    if 'issuer' in cert:
                        iss = [v[0][1] for v in cert['issuer'] if v[0][0] in ('organizationName', 'commonName')]
                        result["issuer"] = " / ".join(iss) if iss else "Desconocido"
                    
                    if 'subject' in cert:
                        sub = [v[0][1] for v in cert['subject'] if v[0][0] in ('organizationName', 'commonName')]
                        result["subject"] = " / ".join(sub) if sub else "Desconocido"

                    if 'notAfter' in cert:
                        # Format: 'Jan 22 12:00:00 2025 GMT'
                        expire_date = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        result["valid_to"] = expire_date.strftime('%Y-%m-%d')
                        delta = expire_date - datetime.datetime.now()
                        result["days_left"] = delta.days
                        result["expired"] = delta.days < 0

    except Exception as e:
        _log(f"[AUDIT] Error leyendo certificado SSL: {e}")
        result["status"] = "error"

    return result


def dhcp_rogue_scan(legit_dhcp_ip: str = "", timeout: int = 10, log_callback: Optional[Callable] = None) -> List[Dict]:
    """
    Simula una petición DHCP DISCOVER para detectar servidores DHCP no autorizados.
    Es un escaneo activo de Capa 2/3 (requiere privilegios root/admin y Scapy).
    """
    def _log(msg):
        if log_callback:
            log_callback(msg)

    _log(f"[AUDIT] Iniciando DHCP Rogue Scan (Timeout: {timeout}s)")
    rogues = []
    
    try:
        from scapy.all import Ether, IP, UDP, BOOTP, DHCP, srp, conf, get_if_raw_hwaddr, get_if_hwaddr

        conf.verb = 0
        from scapy.all import conf as scapy_conf
        
        # MAC de la interfaz activa
        try:
            hw = get_if_raw_hwaddr(scapy_conf.iface)[1]
            mac_str = get_if_hwaddr(scapy_conf.iface)
        except Exception:
            _log("[AUDIT] Error obteniendo la MAC de la interfaz. DHCP test cancelado.")
            return []

        # Crear paquete DHCP Discover
        dhcp_discover = (
            Ether(src=mac_str, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=hw) /
            DHCP(options=[("message-type", "discover"), "end"])
        )

        _log("[AUDIT] Lanzando DHCP Discover...")
        
        # Enviar paquete y escuchar respuestas
        answered, _ = srp(dhcp_discover, multi=True, timeout=timeout, verbose=False)

        for sent, received in answered:
            if received.haslayer(DHCP):
                dhcp_options = received[DHCP].options
                dhcp_server_ip = received[IP].src
                offer_ip = received[BOOTP].yiaddr
                mac_server = received[Ether].src

                msg_type = ""
                domain = ""
                for opt in dhcp_options:
                    if isinstance(opt, tuple):
                        if opt[0] == "message-type":
                            msg_type = {1: "discover", 2: "offer", 3: "request", 5: "ack"}.get(opt[1], str(opt[1]))
                        elif opt[0] == "domain":
                            domain = opt[1].decode('utf-8', errors='ignore') if isinstance(opt[1], bytes) else opt[1]

                if msg_type == "offer":
                    is_rogue = False
                    if legit_dhcp_ip and dhcp_server_ip != legit_dhcp_ip:
                        is_rogue = True
                        _log(f"[AUDIT] 🚨 ALERTA: Rogue DHCP Detectado -> {dhcp_server_ip} (Ofrece IP: {offer_ip})")
                    else:
                        _log(f"[AUDIT] DHCP Offer válido de -> {dhcp_server_ip} (Ofrece IP: {offer_ip})")

                    rogues.append({
                        "dhcp_server_ip": dhcp_server_ip,
                        "server_mac": mac_server.upper(),
                        "offered_ip": offer_ip,
                        "domain": domain,
                        "is_rogue": is_rogue
                    })

    except Exception as e:
        _log(f"[AUDIT] Error en escaneo DHCP: {e}")

    _log(f"[AUDIT] Análisis DHCP finalizado. {len(rogues)} servidores Ofertantes encontrados.")
    return rogues

