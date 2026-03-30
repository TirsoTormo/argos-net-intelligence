"""
Argos Packet Factory - Utilities
================================
Validation and internal helpers for packet crafting.
"""
import ipaddress
from typing import Optional, Callable

def _validate_target(ip: str):
    """Validates IP format before proceeding."""
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        raise ValueError(f"Invalid IPv4 address: {ip}")

def _log_msg(log_callback: Optional[Callable], msg: str):
    """Internal logger helper."""
    if log_callback:
        log_callback(msg)
