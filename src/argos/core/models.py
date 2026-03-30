"""
Argos Pro — Data Models
=============================================
Strict Pydantic schemas for enterprise data integrity.
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field, IPvAnyAddress, field_validator


class DeviceModel(BaseModel):
    """Schema for a discovered network device."""
    ip: str  # String for flexible CIDR/IP handling, but validated by Scapy/Utils
    mac: str = "N/A"
    hostname: str = "Unknown"
    vendor: str = ""
    latency_ms: Optional[float] = None
    method: str = "Unknown"
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    extra_info: Dict[str, Any] = Field(default_factory=dict)

    @field_validator('mac')
    @classmethod
    def normalize_mac(cls, v: str) -> str:
        return v.upper().replace("-", ":")


class ScanResultModel(BaseModel):
    """Schema for a complete network scan."""
    timestamp: datetime = Field(default_factory=datetime.now)
    network_cidr: str
    scan_method: str
    duration_sec: float
    devices_found: int
    devices: List[DeviceModel] = []


class ServiceAuditModel(BaseModel):
    """Schema for L7 service intelligence results."""
    ip: str
    port: int
    status: str
    service: str = "Unknown"
    banner: Optional[str] = None
    tls_info: Dict[str, Any] = Field(default_factory=dict)


class QoSResultModel(BaseModel):
    """Schema for Jitter/VoIP analysis."""
    target_ip: str
    probes_sent: int
    probes_received: int
    loss_pct: float
    avg_latency: float
    jitter: float
    status: str = "ok"


class IDSAlertModel(BaseModel):
    """Schema for Sentinel IDS alerts."""
    timestamp: datetime = Field(default_factory=datetime.now)
    severity: str = "INFO"  # INFO, WARN, CRITICAL
    alert_type: str  # ROGUE_DHCP, ARP_SPOOF, NEW_DEVICE
    description: str
    source_mac: Optional[str] = None
    source_ip: Optional[str] = None
