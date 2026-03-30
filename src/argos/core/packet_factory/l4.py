"""
Argos Packet Factory - Layer 4 (Transport)
=========================================
TCP and UDP Probing operations.
"""
import time
from typing import Optional, List, Dict, Callable
from scapy.all import IP, TCP, UDP, sr1, send, conf
from .utils import _validate_target, _log_msg

def tcp_port_probe(target_ip: str, ports: List[int], log_callback: Optional[Callable] = None) -> List[Dict]:
    """TCP SYN Probe for multiple ports."""
    _validate_target(target_ip)
    _log_msg(log_callback, f"[LAYER 4] TCP SYN Probe → {target_ip} ({len(ports)} ports)")
    
    conf.verb = 0
    results = []
    for p in ports:
        pkt = IP(dst=target_ip) / TCP(dport=p, flags="S")
        try:
            ans = sr1(pkt, timeout=1.5, verbose=False)
            if ans is None:
                results.append({"port": p, "status": "filtered", "flags_received": None})
            elif ans.haslayer(TCP):
                flags = ans.getlayer(TCP).flags
                if flags == 0x12: # SYN-ACK
                    results.append({"port": p, "status": "open", "flags_received": "SA", "ttl": ans.ttl})
                    # Send RST to be polite
                    send(IP(dst=target_ip) / TCP(dport=p, flags="R"), verbose=False)
                elif flags == 0x14: # RST-ACK
                    results.append({"port": p, "status": "closed", "flags_received": "RA"})
                else:
                    results.append({"port": p, "status": "ignored", "flags_received": str(flags)})
        except Exception:
            results.append({"port": p, "status": "error", "flags_received": None})
            
    return results

def send_tcp_custom(target_ip: str, port: int, flags: str = "S", log_callback: Optional[Callable] = None) -> Optional[Dict]:
    """Sends a single TCP packet with custom flags."""
    _validate_target(target_ip)
    _log_msg(log_callback, f"[LAYER 4] TCP Custom Segment ({flags}) → {target_ip}:{port}")
    
    pkt = IP(dst=target_ip) / TCP(dport=port, flags=flags)
    try:
        start = time.perf_counter()
        ans = sr1(pkt, timeout=2, verbose=False)
        elapsed = round((time.perf_counter() - start) * 1000, 2)
        
        if ans and ans.haslayer(TCP):
            return {
                "port": port,
                "status": "responded",
                "flags_received": str(ans.getlayer(TCP).flags),
                "latency_ms": elapsed
            }
    except Exception:
        pass
    return None

def send_udp_probe(target_ip: str, port: int, log_callback: Optional[Callable] = None) -> Dict:
    """Basic UDP Port Probe."""
    _validate_target(target_ip)
    _log_msg(log_callback, f"[LAYER 4] UDP Probe → {target_ip}:{port}")
    
    from scapy.all import ICMP
    pkt = IP(dst=target_ip) / UDP(dport=port)
    try:
        start = time.perf_counter()
        ans = sr1(pkt, timeout=2, verbose=False)
        elapsed = round((time.perf_counter() - start) * 1000, 2)
        
        if ans is None:
            return {"port": port, "status": "open|filtered", "latency_ms": None}
        elif ans.haslayer(ICMP):
            return {"port": port, "status": "closed", "latency_ms": elapsed}
        else:
            return {"port": port, "status": "responded", "latency_ms": elapsed}
    except Exception:
        return {"port": port, "status": "error", "latency_ms": None}

def craft_tcp_packet(dst_ip: str, dport: int, flags: str = "S", sport: Optional[int] = None) -> IP:
    """Crafts a custom TCP packet."""
    ip = IP(dst=dst_ip)
    tcp = TCP(dport=dport, flags=flags)
    if sport:
        tcp.sport = sport
    return ip / tcp
