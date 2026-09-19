"""
alert.py
--------
Shared alert type. Both scan_detector.py and hijack_detector.py emit these
so alert_manager.py / the dashboard can consume one consistent shape
regardless of which detector fired.
"""

import time
from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Alert:
    alert_type: str          # e.g. "PORT_SCAN", "SYN_FLOOD", "SESSION_HIJACK"
    src_ip: str
    severity: Severity
    message: str
    details: dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    network_id: str | None = None   # which department/sensor this came from, in a multi-network deployment

    def to_dict(self):
        return {
            "alert_type": self.alert_type,
            "src_ip": self.src_ip,
            "severity": self.severity.value,
            "message": self.message,
            "details": self.details,
            "timestamp": self.timestamp,
            "network_id": self.network_id,
        }
