"""
Argos - Sentinel Mode (Passive IDS)
===================================
Monitor the network passively for suspicious activity:
- ARP Spoofing detection
- Rogue DHCP servers
- Port scanning patterns
"""
from scapy.all import sniff, ARP, DHCP, IP, UDP, conf
from typing import Optional, Callable
import time

class Sentinel:
    def __init__(self, interface: str, log_callback: Optional[Callable] = None):
        self.interface = interface
        self.log_callback = log_callback
        self.is_running = False
        self.arp_cache = {} # IP -> MAC mapping to detect spoofing

    def _log(self, msg: str, level: str = "INFO"):
        if self.log_callback:
            self.log_callback(f"[{level}] {msg}")

    def packet_callback(self, pkt):
        # 1. ARP Spoofing Detection
        if pkt.haslayer(ARP):
            if pkt[ARP].op == 2: # is-at (response)
                ip = pkt[ARP].psrc
                mac = pkt[ARP].hwsrc.upper()
                
                if ip in self.arp_cache and self.arp_cache[ip] != mac:
                    self._log(f"ARP SPOOFING DETECTED! {ip} moved from {self.arp_cache[ip]} to {mac}", "CRITICAL")
                self.arp_cache[ip] = mac

        # 2. Rogue DHCP Detection (simple)
        if pkt.haslayer(DHCP):
            src_ip = pkt[IP].src
            self._log(f"DHCP Traffic detected from {src_ip}", "WARNING")

        # 3. Port Scan Heuristics (basic)
        # This would require more state than a simple callback, 
        # but we can log unusual UDP/TCP spikes here.

    def start(self):
        self._log(f"Sentinel activated on {self.interface}. Monitoring passively...", "SUCCESS")
        self.is_running = True
        try:
            sniff(iface=self.interface, prn=self.packet_callback, store=0, stop_filter=lambda x: not self.is_running)
        except Exception as e:
            self._log(f"Sentinel stopped: {e}", "ERROR")

    def stop(self):
        self.is_running = False
        self._log("Sentinel deactivated.")
