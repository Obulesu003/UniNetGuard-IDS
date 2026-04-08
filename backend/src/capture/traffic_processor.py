"""Traffic processing and feature extraction"""

import time
from datetime import datetime
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass, field
from collections import defaultdict
from threading import Lock

from .packet_capture import CapturedPacket


@dataclass
class PacketStats:
    total_packets: int = 0
    total_bytes: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    icmp_packets: int = 0
    other_packets: int = 0
    tcp_bytes: int = 0
    udp_bytes: int = 0
    duration: float = 0
    packets_per_second: float = 0
    bytes_per_second: float = 0
    avg_packet_size: float = 0
    unique_src_ips: int = 0
    unique_dst_ips: int = 0
    unique_src_ports: int = 0
    unique_dst_ports: int = 0
    start_time: float = field(default_factory=time.time)
    last_update: float = field(default_factory=time.time)

    protocol_distribution: Dict[str, int] = field(default_factory=dict)
    top_src_ips: Dict[str, int] = field(default_factory=dict)
    top_dst_ips: Dict[str, int] = field(default_factory=dict)
    top_dst_ports: Dict[str, int] = field(default_factory=dict)

    web_payload_count: int = 0
    sql_injection_count: int = 0
    xss_count: int = 0
    brute_force_count: int = 0
    port_scan_sources: Dict[str, set] = field(default_factory=dict)
    dos_packets: int = 0
    bot_beacon_score: float = 0

    def to_dict(self) -> Dict[str, Any]:
        total = self.total_packets or 1
        return {
            'total_packets': self.total_packets,
            'packet_count': self.total_packets,
            'total_bytes': self.total_bytes,
            'byte_count': self.total_bytes,
            'tcp_packets': self.tcp_packets,
            'udp_packets': self.udp_packets,
            'icmp_packets': self.icmp_packets,
            'other_packets': self.other_packets,
            'tcp_ratio': self.tcp_packets / total,
            'udp_ratio': self.udp_packets / total,
            'icmp_ratio': self.icmp_packets / total,
            'duration': round(self.duration, 2),
            'packets_per_second': round(self.packets_per_second, 2),
            'bytes_per_second': round(self.bytes_per_second, 2),
            'avg_packet_size': round(self.avg_packet_size, 2),
            'unique_src_ips': self.unique_src_ips,
            'unique_dst_ips': self.unique_dst_ips,
            'unique_src_ports': self.unique_src_ports,
            'unique_dst_ports': self.unique_dst_ports,
            'protocol_distribution': dict(sorted(self.protocol_distribution.items(), key=lambda x: x[1], reverse=True)[:5]),
            'top_src_ips': dict(sorted(self.top_src_ips.items(), key=lambda x: x[1], reverse=True)[:5]),
            'top_dst_ips': dict(sorted(self.top_dst_ips.items(), key=lambda x: x[1], reverse=True)[:5]),
            'top_dst_ports': dict(sorted(self.top_dst_ports.items(), key=lambda x: x[1], reverse=True)[:5]),
            'sql_injection_count': self.sql_injection_count,
            'xss_count': self.xss_count,
            'web_payload_count': self.web_payload_count,
            'brute_force_count': self.brute_force_count,
            'port_scan_sources': {k: list(v) for k, v in self.port_scan_sources.items()},
            'dos_packets': self.dos_packets,
            'bot_beacon_score': round(self.bot_beacon_score, 2)
        }


class TrafficProcessor:
    def __init__(self, window_size: int = 60):
        self.window_size = window_size
        self.packets: list = []
        self.max_packets = 10000
        self.stats = PacketStats()
        self._lock = Lock()
        self._callbacks: List[Callable] = []

        self._ssh_attempts: Dict[str, List[float]] = defaultdict(list)
        self._port_scan_hits: Dict[str, Dict[int, List[float]]] = defaultdict(lambda: defaultdict(list))
        self._dos_tracker: Dict[str, List[float]] = defaultdict(list)
        self._beacon_tracker: Dict[str, List[float]] = defaultdict(list)

    def add_packet(self, packet: CapturedPacket):
        with self._lock:
            self.packets.append(packet)
            if len(self.packets) > self.max_packets:
                self.packets = self.packets[-self.max_packets:]
            self._update_stats(packet)

            for callback in self._callbacks:
                try:
                    callback(packet, self.stats)
                except Exception:
                    pass

    def _update_stats(self, packet: CapturedPacket):
        self.stats.total_packets += 1
        self.stats.total_bytes += packet.length
        self.stats.last_update = time.time()

        protocol = packet.protocol.upper()
        self.stats.protocol_distribution[protocol] = self.stats.protocol_distribution.get(protocol, 0) + 1

        if protocol == 'TCP':
            self.stats.tcp_packets += 1
            self.stats.tcp_bytes += packet.length
        elif protocol == 'UDP':
            self.stats.udp_packets += 1
            self.stats.udp_bytes += packet.length
        elif protocol == 'ICMP':
            self.stats.icmp_packets += 1
        else:
            self.stats.other_packets += 1

        self.stats.top_src_ips[packet.src_ip] = self.stats.top_src_ips.get(packet.src_ip, 0) + 1
        self.stats.top_dst_ips[packet.dst_ip] = self.stats.top_dst_ips.get(packet.dst_ip, 0) + 1

        if packet.dst_port > 0:
            self.stats.top_dst_ports[packet.dst_port] = self.stats.top_dst_ports.get(packet.dst_port, 0) + 1

        self.stats.duration = time.time() - self.stats.start_time
        self.stats.packets_per_second = self.stats.total_packets / max(self.stats.duration, 0.001)
        self.stats.bytes_per_second = self.stats.total_bytes / max(self.stats.duration, 0.001)
        self.stats.avg_packet_size = self.stats.total_bytes / max(self.stats.total_packets, 1)

        self.stats.unique_src_ips = len(self.stats.top_src_ips)
        self.stats.unique_dst_ips = len(self.stats.top_dst_ips)
        self.stats.unique_src_ports = len(set(p.src_port for p in self.packets if p.src_port > 0))
        self.stats.unique_dst_ports = len(self.stats.top_dst_ports)

        payload = getattr(packet, 'payload', '') or ''
        payload_lower = payload.lower()

        sql_dangerous = [
            "union select", "union all select", "drop table", "drop database",
            "exec(", "execute(", "xp_", "sp_", "0x", "char(",
            "benchmark(", "sleep(", "waitfor delay",
            "load_file", "into outfile", "into dumpfile"
        ]
        sql_injection_indicators = [" or 1=1", "' or '1'='1", "--", "/*", "*/",
                                    "1=1", "' or \"", "or null", "having "]
        has_dangerous = any(p in payload_lower for p in sql_dangerous)
        has_indicators = sum(1 for p in sql_injection_indicators if p in payload_lower)
        if has_dangerous or has_indicators >= 2:
            self.stats.sql_injection_count += 1

        xss_dangerous = [
            "<script", "</script", "javascript:", "onerror=", "onload=",
            "onmouseover=", "onfocus=", "onblur=", "document.cookie",
            "document.write", "window.location", "eval(", "<svg", "<body",
            "innerhtml", "outerhtml", "vbscript:"
        ]
        if any(p in payload_lower for p in xss_dangerous):
            self.stats.xss_count += 1

        web_suspicious = ["<script", "onerror=", "onload=", "javascript:",
                          "union select", "drop table", "eval("]
        if any(p in payload_lower for p in web_suspicious) and packet.dst_port in [80, 443, 8080, 8443]:
            self.stats.web_payload_count += 1

        self._track_ssh_attempts(packet)
        self._track_port_scan(packet)
        self._track_dos(packet, protocol)
        self._track_bot_beacon(packet)

    def _track_ssh_attempts(self, packet: CapturedPacket):
        if packet.dst_port != 22:
            return
        now = time.time()
        self._ssh_attempts[packet.src_ip] = [
            t for t in self._ssh_attempts[packet.src_ip] if now - t < 60
        ]
        self._ssh_attempts[packet.src_ip].append(now)
        if len(self._ssh_attempts[packet.src_ip]) >= 10:
            self.stats.brute_force_count = max(
                self.stats.brute_force_count,
                len(self._ssh_attempts[packet.src_ip])
            )

    def _track_port_scan(self, packet: CapturedPacket):
        now = time.time()
        src_ip = packet.src_ip

        if src_ip in self._port_scan_hits:
            for port in list(self._port_scan_hits[src_ip].keys()):
                self._port_scan_hits[src_ip][port] = [
                    t for t in self._port_scan_hits[src_ip][port] if now - t < 30
                ]
                if not self._port_scan_hits[src_ip][port]:
                    del self._port_scan_hits[src_ip][port]

        if packet.protocol.upper() == 'TCP':
            self._port_scan_hits[src_ip][packet.dst_port].append(now)
            unique_ports = len(self._port_scan_hits[src_ip])
            if unique_ports >= 15:
                if src_ip not in self.stats.port_scan_sources:
                    self.stats.port_scan_sources[src_ip] = set()
                self.stats.port_scan_sources[src_ip].update(self._port_scan_hits[src_ip].keys())

    def _track_dos(self, packet: CapturedPacket, protocol: str):
        now = time.time()
        src_ip = packet.src_ip

        self._dos_tracker[src_ip] = [
            t for t in self._dos_tracker[src_ip] if now - t < 10
        ]

        if protocol == 'UDP' and packet.length > 1000:
            self._dos_tracker[src_ip].append(now)
            if len(self._dos_tracker[src_ip]) >= 20:
                self.stats.dos_packets = max(self.stats.dos_packets, len(self._dos_tracker[src_ip]))

    def _track_bot_beacon(self, packet: CapturedPacket):
        now = time.time()
        suspicious_ports = [4444, 5555]

        if packet.dst_port in suspicious_ports and packet.length < 200:
            self._beacon_tracker[packet.dst_ip].append(now)
            timestamps = self._beacon_tracker[packet.dst_ip]
            if len(timestamps) >= 3:
                intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
                if intervals:
                    mean_interval = sum(intervals) / len(intervals)
                    if mean_interval > 0:
                        std_dev = (sum((x - mean_interval)**2 for x in intervals) / len(intervals)) ** 0.5
                        if std_dev / mean_interval < 0.2 and 30 < mean_interval < 120:
                            self.stats.bot_beacon_score = min(
                                self.stats.bot_beacon_score + 1.0,
                                10.0
                            )

    def get_current_features(self) -> Dict[str, Any]:
        with self._lock:
            features = self.stats.to_dict()
            features['packet_count'] = features.get('packet_count', features.get('total_packets', 0))
            features['byte_count'] = features.get('byte_count', features.get('total_bytes', 0))
            features['total_packets'] = features.get('total_packets', features.get('packet_count', 0))
            features['total_bytes'] = features.get('total_bytes', features.get('byte_count', 0))
            unique_dst_ports = features['unique_dst_ports']
            if unique_dst_ports >= 15:
                features['port_scan_score'] = min(unique_dst_ports / 50, 1.0)
            else:
                features['port_scan_score'] = 0.0
            return features

    def get_stats(self) -> PacketStats:
        with self._lock:
            return PacketStats(
                total_packets=self.stats.total_packets,
                total_bytes=self.stats.total_bytes,
                tcp_packets=self.stats.tcp_packets,
                udp_packets=self.stats.udp_packets,
                icmp_packets=self.stats.icmp_packets,
                other_packets=self.stats.other_packets,
                tcp_bytes=self.stats.tcp_bytes,
                udp_bytes=self.stats.udp_bytes,
                duration=self.stats.duration,
                packets_per_second=self.stats.packets_per_second,
                bytes_per_second=self.stats.bytes_per_second,
                avg_packet_size=self.stats.avg_packet_size,
                unique_src_ips=self.stats.unique_src_ips,
                unique_dst_ips=self.stats.unique_dst_ips,
                protocol_distribution=dict(self.stats.protocol_distribution),
                top_src_ips=dict(sorted(self.stats.top_src_ips.items(), key=lambda x: x[1], reverse=True)[:5]),
                top_dst_ips=dict(sorted(self.stats.top_dst_ips.items(), key=lambda x: x[1], reverse=True)[:5]),
                top_dst_ports=dict(sorted(self.stats.top_dst_ports.items(), key=lambda x: x[1], reverse=True)[:5]),
                web_payload_count=self.stats.web_payload_count,
                sql_injection_count=self.stats.sql_injection_count,
                xss_count=self.stats.xss_count,
                brute_force_count=self.stats.brute_force_count,
                port_scan_sources={k: list(v) for k, v in self.stats.port_scan_sources.items()},
                dos_packets=self.stats.dos_packets,
                bot_beacon_score=self.stats.bot_beacon_score
            )

    def register_callback(self, callback: Callable):
        self._callbacks.append(callback)

    def get_recent_packets(self, count: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            packets = self.packets[-count:]
            return [p.to_dict() for p in packets]

    def reset(self):
        with self._lock:
            self.packets.clear()
            self.stats = PacketStats()
            self._ssh_attempts.clear()
            self._port_scan_hits.clear()
            self._dos_tracker.clear()
            self._beacon_tracker.clear()
