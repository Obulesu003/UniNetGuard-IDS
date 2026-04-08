import asyncio
from datetime import datetime
from typing import Optional, Callable
from src.capture.packet_capture import PacketInfo
from src.analysis.detector import DetectionResult, SignatureEngine, AnomalyEngine
from src.core.database import async_session
from src.core.schemas import Alert, TrafficStats, CapturedPacket
from sqlalchemy import select, func


class AlertManager:
    def __init__(self):
        self.signature_engine = SignatureEngine()
        self.anomaly_engine = AnomalyEngine()
        self._subscribers: list[Callable[[dict], None]] = []
        self._lock = asyncio.Lock()
        self._alert_count = 0
        self._last_stats_save = datetime.now()
        self._stats_interval = 5

        # Running stats
        self._pps = 0
        self._bps = 0
        self._tcp = 0
        self._udp = 0
        self._icmp = 0
        self._other = 0
        self._total_packets = 0
        self._total_bytes = 0
        self._last_pps_check = datetime.now()
        self._recent_packets = 0
        self._recent_bytes = 0
        self._recent_alert_ids: list[str] = []
        self._max_stored_alerts = 1000

    def subscribe(self, callback: Callable[[dict], None]):
        self._subscribers.append(callback)

    async def analyze_packet(self, packet: PacketInfo) -> list[Alert]:
        alerts_created = []

        # Update running stats
        self._total_packets += 1
        self._total_bytes += packet.length
        self._recent_packets += 1
        self._recent_bytes += packet.length

        protocol_map = {"TCP": "_tcp", "UDP": "_udp", "ICMP": "_icmp"}
        attr = protocol_map.get(packet.protocol, "_other")
        current = getattr(self, attr) + 1
        setattr(self, attr, current)

        # Detect
        sig_results = self.signature_engine.detect(packet)
        anomaly_results = self.anomaly_engine.detect(packet)
        all_results = sig_results + anomaly_results

        # Store packet
        alert_id_for_packet = None
        is_alert = len(all_results) > 0

        for result in all_results:
            alert = await self._create_alert(packet, result, "signature")
            if alert:
                alerts_created.append(alert)
                if alert_id_for_packet is None:
                    alert_id_for_packet = alert.id

        # Store packet in DB
        await self._store_packet(packet, is_alert, alert_id_for_packet)

        # Save stats periodically
        await self._maybe_save_stats()

        return alerts_created

    async def _store_packet(self, packet: PacketInfo, is_alert: bool, alert_id: Optional[str]):
        try:
            async with async_session() as session:
                raw_hex = ""
                if packet.raw_data:
                    raw_hex = packet.raw_data[:64].hex()
                elif packet.payload_preview:
                    # Synthetic packet - create hex from payload
                    raw_hex = packet.payload_preview[:64].hex()

                pkt = CapturedPacket(
                    src_ip=packet.src_ip,
                    dst_ip=packet.dst_ip,
                    src_port=packet.src_port,
                    dst_port=packet.dst_port,
                    protocol=packet.protocol,
                    length=packet.length,
                    ttl=packet.ttl,
                    ip_length=packet.ip_length,
                    tcp_flags=packet.flags,
                    tcp_seq=packet.tcp_seq,
                    tcp_ack=packet.tcp_ack,
                    window_size=packet.window_size,
                    checksum=packet.checksum,
                    dns_query=packet.dns_query or None,
                    http_method=packet.http_method or None,
                    payload_preview=packet.payload_preview.decode("utf-8", errors="replace") if packet.payload_preview else None,
                    raw_hex=raw_hex,
                    is_alert=is_alert,
                    alert_id=alert_id,
                )
                session.add(pkt)
                await session.commit()
        except Exception:
            pass

    async def _create_alert(self, packet: PacketInfo, result: DetectionResult, method: str) -> Optional[Alert]:
        async with self._lock:
            alert = Alert(
                severity=result.severity,
                category=result.category,
                title=result.title,
                description=result.description,
                source_ip=packet.src_ip,
                dest_ip=packet.dst_ip,
                source_port=packet.src_port,
                dest_port=packet.dst_port,
                protocol=packet.protocol,
                signature_id=result.signature_id,
                detection_method=method,
                extra_data=result.metadata,
            )

            try:
                async with async_session() as session:
                    session.add(alert)
                    await session.commit()
                    await session.refresh(alert)
                    self._alert_count += 1
                    alert_dict = self._alert_to_dict(alert)
                    await self._notify_subscribers(alert_dict)
                    return alert
            except Exception:
                return None

    def _alert_to_dict(self, alert: Alert) -> dict:
        return {
            "id": alert.id,
            "timestamp": alert.timestamp.isoformat() if alert.timestamp else datetime.now().isoformat(),
            "severity": alert.severity,
            "category": alert.category,
            "title": alert.title,
            "description": alert.description or "",
            "source_ip": alert.source_ip,
            "dest_ip": alert.dest_ip or "",
            "source_port": alert.source_port or 0,
            "dest_port": alert.dest_port or 0,
            "protocol": alert.protocol or "unknown",
            "signature_id": alert.signature_id or "",
            "detection_method": alert.detection_method,
            "resolved": alert.resolved,
        }

    async def _notify_subscribers(self, alert_data: dict):
        for callback in self._subscribers:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(alert_data)
                else:
                    callback(alert_data)
            except Exception:
                pass

    async def _maybe_save_stats(self):
        now = datetime.now()
        if (now - self._last_stats_save).total_seconds() < self._stats_interval:
            return

        elapsed = (now - self._last_pps_check).total_seconds()
        self._pps = round(self._recent_packets / elapsed) if elapsed > 0 else 0
        self._bps = round(self._recent_bytes / elapsed) if elapsed > 0 else 0

        self._recent_packets = 0
        self._recent_bytes = 0
        self._last_pps_check = now
        self._last_stats_save = now

        try:
            async with async_session() as session:
                active_alerts = await session.scalar(
                    select(func.count(Alert.id)).where(Alert.resolved == False)
                )
                stats = TrafficStats(
                    packets_per_second=self._pps,
                    bytes_per_second=self._bps,
                    total_packets=self._total_packets,
                    total_bytes=self._total_bytes,
                    active_alerts=active_alerts or 0,
                    tcp_count=self._tcp,
                    udp_count=self._udp,
                    icmp_count=self._icmp,
                    other_count=self._other,
                )
                session.add(stats)
                await session.commit()
        except Exception:
            pass

    async def get_active_alert_count(self) -> int:
        try:
            async with async_session() as session:
                count = await session.scalar(
                    select(func.count(Alert.id)).where(Alert.resolved == False)
                )
                return count or 0
        except Exception:
            return 0

    def reset_stats(self):
        """Reset all running counters (call on capture stop)."""
        self._pps = 0
        self._bps = 0
        self._tcp = 0
        self._udp = 0
        self._icmp = 0
        self._other = 0
        self._total_packets = 0
        self._total_bytes = 0
        self._recent_packets = 0
        self._recent_bytes = 0
        self._alert_count = 0

    async def resolve_all_active(self, resolved_by: str = "system") -> int:
        """Resolve all currently active (unresolved) alerts. Returns count resolved."""
        try:
            async with async_session() as session:
                result = await session.execute(
                    select(Alert).where(Alert.resolved == False)
                )
                alerts = result.scalars().all()
                for alert in alerts:
                    alert.resolved = True
                    alert.resolved_at = datetime.now()
                    alert.resolved_by = resolved_by
                await session.commit()
                return len(alerts)
        except Exception:
            return 0

    def get_live_stats(self) -> dict:
        return {
            "packets_per_second": self._pps,
            "bytes_per_second": self._bps,
            "total_packets": self._total_packets,
            "total_bytes": self._total_bytes,
            "protocols": {
                "tcp": self._tcp,
                "udp": self._udp,
                "icmp": self._icmp,
                "other": self._other,
            },
        }


alert_manager = AlertManager()
