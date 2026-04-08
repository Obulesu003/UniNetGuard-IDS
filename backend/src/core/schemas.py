from sqlalchemy import Column, String, Integer, BigInteger, Boolean, DateTime, Text, JSON
from sqlalchemy.sql import func
from src.core.database import Base
import uuid


def generate_uuid():
    return str(uuid.uuid4())


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    severity = Column(String(10), nullable=False, index=True)
    category = Column(String(50), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    source_ip = Column(String(45), nullable=False, index=True)
    dest_ip = Column(String(45), nullable=True)
    source_port = Column(Integer, nullable=True)
    dest_port = Column(Integer, nullable=True)
    protocol = Column(String(20), nullable=True)
    signature_id = Column(String(100), nullable=True)
    detection_method = Column(String(30), nullable=False)
    extra_data = Column(JSON, default={})
    resolved = Column(Boolean, default=False, index=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    resolved_by = Column(String(100), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class CapturedPacket(Base):
    __tablename__ = "captured_packets"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    src_ip = Column(String(45), nullable=False, index=True)
    dst_ip = Column(String(45), nullable=False, index=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String(20), nullable=False, index=True)
    length = Column(Integer, default=0)
    ttl = Column(Integer, default=64)
    ip_length = Column(Integer, default=0)
    tcp_flags = Column(String(20), nullable=True)
    tcp_seq = Column(BigInteger, default=0)
    tcp_ack = Column(BigInteger, default=0)
    window_size = Column(Integer, default=0)
    checksum = Column(Integer, nullable=True)
    dns_query = Column(String(255), nullable=True)
    http_method = Column(String(20), nullable=True)
    payload_preview = Column(Text, nullable=True)
    raw_hex = Column(Text, nullable=True)  # First 64 bytes as hex
    is_alert = Column(Boolean, default=False, index=True)
    alert_id = Column(String(36), nullable=True)


class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(100), nullable=False, unique=True)
    rule_text = Column(Text, nullable=False)
    category = Column(String(50), nullable=True)
    severity = Column(String(10), nullable=False, default="medium")
    is_active = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class TrafficStats(Base):
    __tablename__ = "traffic_stats"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    packets_per_second = Column(Integer, default=0)
    bytes_per_second = Column(Integer, default=0)
    total_packets = Column(BigInteger, default=0)
    total_bytes = Column(BigInteger, default=0)
    active_alerts = Column(Integer, default=0)
    tcp_count = Column(Integer, default=0)
    udp_count = Column(Integer, default=0)
    icmp_count = Column(Integer, default=0)
    other_count = Column(Integer, default=0)

