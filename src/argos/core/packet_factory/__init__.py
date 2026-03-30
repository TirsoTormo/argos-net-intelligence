"""
Argos Packet Factory Package
============================
A modular suite for low-level packet crafting and network probing.
Categorized by OSI layers for better maintainability.
"""

from .l2 import send_arp_request, craft_ethernet_frame
from .l3 import send_icmp_ping, manual_traceroute
from .l4 import (
    tcp_port_probe, 
    send_tcp_custom, 
    send_udp_probe,
    craft_tcp_packet
)
from .utils import _validate_target

# Visual Builder Helpers (Basic)
def craft_ip_packet(dst_ip: str, src_ip: Optional[str] = None, ttl: int = 64) -> IP:
    from scapy.all import IP
    pkt = IP(dst=dst_ip, ttl=ttl)
    if src_ip:
        pkt.src = src_ip
    return pkt

def send_custom_packet(pkt, timeout: int = 2, layer2: bool = False, log_callback: Optional[Callable] = None):
    from scapy.all import srp1, sr1, conf
    conf.verb = 0
    try:
        if layer2:
            ans = srp1(pkt, timeout=timeout, verbose=False)
        else:
            ans = sr1(pkt, timeout=timeout, verbose=False)
        
        if ans:
            if log_callback:
                log_callback(f"[PACKET FACTORY] Response received: {ans.summary()}")
            return ans
    except Exception as e:
        if log_callback:
            log_callback(f"[PACKET FACTORY] Error: {e}")
    return None

def get_common_port_groups() -> dict:
    """Returns preset port groups for scanning."""
    return {
        "top20": [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080],
        "web": [80, 443, 8080, 8443, 3000, 5000],
        "infra": [22, 23, 53, 161, 445, 3389],
        "db": [1433, 3306, 5432, 6379, 27017]
    }
