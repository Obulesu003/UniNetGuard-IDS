import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional
from src.capture.packet_capture import PacketInfo


@dataclass
class DetectionResult:
    detected: bool
    title: str
    severity: str  # low, medium, high, critical
    category: str
    description: str
    signature_id: Optional[str] = None
    metadata: dict = field(default_factory=dict)


# ─────────────────────────────────────────────────────────────
# SIGNATURE ENGINE — Snort-style pattern matching
# ─────────────────────────────────────────────────────────────

SIGNATURE_RULES = [
    {
        "name": "TCP SYN-FIN Scan",
        "pattern": {"protocol": "TCP", "flags": "SF"},
        "severity": "high",
        "category": "port_scan",
        "description": "TCP SYN+FIN flags combined — abnormal scan pattern",
        "sid": 1002,
    },
    {
        "name": "TCP NULL Scan",
        "pattern": {"protocol": "TCP", "flags": "0"},
        "severity": "high",
        "category": "port_scan",
        "description": "TCP NULL scan — no flags set",
        "sid": 1003,
    },
    {
        "name": "TCP Xmas Scan",
        "pattern": {"protocol": "TCP", "flags": "FPU"},
        "severity": "high",
        "category": "port_scan",
        "description": "TCP Xmas scan — FIN, PSH, URG flags",
        "sid": 1004,
    },
]


class SignatureEngine:
    """Pattern-matching based detection."""

    def __init__(self, rules: list[dict] = None):
        self.rules = rules or SIGNATURE_RULES

    def detect(self, packet: PacketInfo) -> list[DetectionResult]:
        results = []
        for rule in self.rules:
            if self._match_rule(packet, rule):
                results.append(DetectionResult(
                    detected=True,
                    title=rule["name"],
                    severity=rule["severity"],
                    category=rule["category"],
                    description=rule["description"],
                    signature_id=str(rule["sid"]),
                    metadata={"rule": rule["name"]},
                ))
        return results

    def _match_rule(self, packet: PacketInfo, rule: dict) -> bool:
        pattern = rule["pattern"]

        if pattern.get("protocol") and packet.protocol != pattern["protocol"]:
            return False

        if pattern.get("flags") and packet.flags != pattern["flags"]:
            return False

        if pattern.get("dst_port") and packet.dst_port != pattern["dst_port"]:
            return False

        if pattern.get("src_port") and packet.src_port != pattern["src_port"]:
            return False

        return True


# ─────────────────────────────────────────────────────────────
# ANOMALY ENGINE — Statistical detection
# ─────────────────────────────────────────────────────────────

class AnomalyEngine:
    """Statistical anomaly detection for port scanning and floods."""

    def __init__(self, window_seconds: int = 60):
        self.window = timedelta(seconds=window_seconds)
        # Track (src_ip -> list of (timestamp, dest_ports))
        self.port_scan_tracker: dict[str, list[tuple[datetime, set[int]]]] = defaultdict(list)
        # Track (src_ip -> list of (timestamp, count))
        self.flood_tracker: dict[str, list[tuple[datetime, int]]] = defaultdict(list)
        # Protocol baseline
        self.protocol_counts: dict[str, int] = defaultdict(int)
        self.total_packets = 0

    def detect(self, packet: PacketInfo) -> list[DetectionResult]:
        results = []
        now = datetime.now()

        # Track protocol distribution
        self.protocol_counts[packet.protocol] += 1
        self.total_packets += 1

        # Port scan detection
        scan_result = self._check_port_scan(packet, now)
        if scan_result:
            results.append(scan_result)

        # Flood detection
        flood_result = self._check_flood(packet, now)
        if flood_result:
            results.append(flood_result)

        # Clean old entries
        self._cleanup_old_entries(now)

        return results

    def _check_port_scan(self, packet: PacketInfo, now: datetime) -> Optional[DetectionResult]:
        tracker = self.port_scan_tracker[packet.src_ip]
        tracker.append((now, {packet.dst_port}))

        # Count unique ports in window
        recent = [(t, ports) for t, ports in tracker if now - t <= self.window]
        unique_ports = set()
        for _, ports in recent:
            unique_ports.update(ports)

        self.port_scan_tracker[packet.src_ip] = recent

        # Port scan: many ports, few packets per port
        # Require higher threshold to reduce false positives from normal traffic
        if len(recent) > 30 and len(unique_ports) > 20 and len(unique_ports) / len(recent) > 0.8:
            return DetectionResult(
                detected=True,
                title="Port Scan Detected",
                severity="high",
                category="port_scan",
                description=f"Source {packet.src_ip} contacted {len(unique_ports)} unique ports in 60s — likely port scan",
                signature_id="anomaly_001",
                metadata={
                    "src_ip": packet.src_ip,
                    "unique_ports": len(unique_ports),
                    "total_attempts": len(recent),
                },
            )
        return None

    def _check_flood(self, packet: PacketInfo, now: datetime) -> Optional[DetectionResult]:
        tracker = self.flood_tracker[packet.src_ip]
        tracker.append((now, 1))

        recent = [(t, c) for t, c in tracker if now - t <= timedelta(seconds=10)]

        if len(recent) > 100:
            self.flood_tracker[packet.src_ip] = recent
            return DetectionResult(
                detected=True,
                title="Traffic Flood Detected",
                severity="medium",
                category="flood",
                description=f"Source {packet.src_ip} sent {len(recent)} packets in 10s — potential flood",
                signature_id="anomaly_002",
                metadata={
                    "src_ip": packet.src_ip,
                    "packets_in_window": len(recent),
                },
            )
        self.flood_tracker[packet.src_ip] = recent
        return None

    def _cleanup_old_entries(self, now: datetime):
        cutoff = now - self.window
        for ip in list(self.port_scan_tracker.keys()):
            self.port_scan_tracker[ip] = [
                (t, p) for t, p in self.port_scan_tracker[ip] if t > cutoff
            ]
            if not self.port_scan_tracker[ip]:
                del self.port_scan_tracker[ip]

        for ip in list(self.flood_tracker.keys()):
            self.flood_tracker[ip] = [
                (t, c) for t, c in self.flood_tracker[ip] if t > cutoff
            ]
            if not self.flood_tracker[ip]:
                del self.flood_tracker[ip]

    def get_stats(self) -> dict:
        return {
            "tracked_ips": len(self.port_scan_tracker),
            "flood_tracked_ips": len(self.flood_tracker),
            "total_packets": self.total_packets,
            "protocol_distribution": dict(self.protocol_counts),
        }
