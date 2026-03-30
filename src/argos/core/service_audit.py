"""
L7 Service Intelligence Module (Argos v1.2.0)
Extracts service banners and hardware metadata (SNMP) bypassing the transport layer.
"""
import socket
import asyncio
from typing import Optional, Callable, Dict, Any
from argos.core.models import ServiceAuditModel


async def grab_banner_async(
    dst_ip: str, 
    port: int, 
    timeout: float = 2.0, 
    log_callback: Optional[Callable] = None
) -> str:
    """
    Attempts to connect to the port asynchronously and read its banner.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(dst_ip, port), 
            timeout=timeout
        )
        
        # Protocol-specific triggers
        if port in [80, 8080]:
            writer.write(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            await writer.drain()
        
        banner_raw = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        writer.close()
        await writer.wait_closed()

        if not banner_raw:
            return ""
            
        banner = banner_raw.decode('utf-8', errors='ignore').strip()
        if banner:
            lines = [line.strip() for line in banner.split('\n') if line.strip()]
            if port in [80, 8080, 443]:
                for line in lines:
                    if line.lower().startswith("server:"):
                        return line[7:].strip()[:80]
            if lines:
                return lines[0][:80]

    except (asyncio.TimeoutError, ConnectionRefusedError, Exception):
        pass
        
    return ""

def grab_banner(dst_ip: str, port: int, timeout: float = 2.0) -> str:
    """Synchronous wrapper for grab_banner_async."""
    try:
        return asyncio.run(grab_banner_async(dst_ip, port, timeout))
    except Exception:
        return ""


def snmp_sysdescr(
    dst_ip: str, 
    community: str = "public", 
    timeout: float = 1.5, 
    log_callback: Optional[Callable] = None
) -> Optional[str]:
    """
    Performs a basic SNMP v2c query to obtain the sysDescr 
    (system identification, hardware, and OS).
    """
    from argos.core.packet_factory import _validate_target
    _validate_target(dst_ip)
    from scapy.all import IP, UDP, sr1
    from scapy.layers.snmp import SNMP, SNMPget, SNMPvarbind, ASN1_OID

    def _log(msg):
        if log_callback:
            log_callback(msg)

    _log(f"[LAYER 7] SNMP sysDescr probe → {dst_ip} (community: '{community}')")

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
                            _log(f"[LAYER 7] SNMP Response: {desc[:60]}...")
                            return desc
                        elif isinstance(val, bytes):
                            desc = val.decode('utf-8', errors='ignore')
                            _log(f"[LAYER 7] SNMP Response: {desc[:60]}...")
                            return desc
        
        _log("[LAYER 7] No valid SNMP response")
    except Exception as e:
        _log(f"[LAYER 7] SNMP Error: {e}")
        
    return None
