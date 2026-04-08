from fastapi import APIRouter, Depends, HTTPException, Query, Body
from pydantic import field_validator
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession
from src.core.database import get_db
from src.core.schemas import Alert, DetectionRule, TrafficStats, CapturedPacket
from src.core.alert_manager import alert_manager
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timedelta
import asyncio

router = APIRouter()


# ── Response Models ─────────────────────────────────────────

class BulkResolveRequest(BaseModel):
    alert_ids: list[str]
    resolved_by: str = "system"


class AlertResponse(BaseModel):
    id: str
    timestamp: Optional[str] = None
    severity: str
    category: str
    title: str
    description: Optional[str] = None
    source_ip: str
    dest_ip: Optional[str] = None
    source_port: Optional[int] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None
    signature_id: Optional[str] = None
    detection_method: str
    resolved: bool
    resolved_at: Optional[str] = None
    resolved_by: Optional[str] = None

    @field_validator('timestamp', 'resolved_at', mode='before')
    @classmethod
    def dt_to_str(cls, v):
        if hasattr(v, 'isoformat'):
            return v.isoformat()
        return v

    class Config:
        from_attributes = True


class AlertListResponse(BaseModel):
    success: bool = True
    total: int
    alerts: list[AlertResponse]


class RuleResponse(BaseModel):
    id: str
    name: str
    rule_text: str
    category: Optional[str] = None
    severity: str
    is_active: bool
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    @field_validator('created_at', 'updated_at', mode='before')
    @classmethod
    def dt_to_str(cls, v):
        if hasattr(v, 'isoformat'):
            return v.isoformat()
        return v

    class Config:
        from_attributes = True


class RuleCreate(BaseModel):
    name: str
    rule_text: str
    category: Optional[str] = None
    severity: str = "medium"


class PacketResponse(BaseModel):
    id: str
    timestamp: Optional[str] = None
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str
    length: int
    ttl: int
    tcp_flags: Optional[str] = None
    tcp_seq: int = 0
    tcp_ack: int = 0
    window_size: int = 0
    dns_query: Optional[str] = None
    http_method: Optional[str] = None
    payload_preview: Optional[str] = None
    raw_hex: Optional[str] = None
    is_alert: bool
    alert_id: Optional[str] = None

    @field_validator('timestamp', mode='before')
    @classmethod
    def dt_to_str(cls, v):
        if hasattr(v, 'isoformat'):
            return v.isoformat()
        return v

    class Config:
        from_attributes = True


class PacketListResponse(BaseModel):
    success: bool = True
    total: int
    packets: list[PacketResponse]


class PacketDetailResponse(BaseModel):
    success: bool = True
    packet: PacketResponse
    hex_dump: Optional[str]


# ── Alert Endpoints ─────────────────────────────────────────

@router.get("/alerts", response_model=AlertListResponse)
async def list_alerts(
    severity: Optional[str] = None,
    category: Optional[str] = None,
    resolved: Optional[bool] = None,
    method: Optional[str] = None,
    limit: int = Query(default=50, le=500),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    query = select(Alert).order_by(desc(Alert.timestamp))
    count_query = select(func.count(Alert.id))

    if severity:
        query = query.where(Alert.severity == severity)
        count_query = count_query.where(Alert.severity == severity)
    if category:
        query = query.where(Alert.category == category)
        count_query = count_query.where(Alert.category == category)
    if resolved is not None:
        query = query.where(Alert.resolved == resolved)
        count_query = count_query.where(Alert.resolved == resolved)
    if method:
        query = query.where(Alert.detection_method == method)
        count_query = count_query.where(Alert.detection_method == method)

    total = (await db.execute(count_query)).scalar() or 0
    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    alerts = result.scalars().all()

    return AlertListResponse(
        total=total,
        alerts=[AlertResponse.model_validate(a) for a in alerts],
    )


@router.get("/alerts/{alert_id}", response_model=AlertResponse)
async def get_alert(alert_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return AlertResponse.model_validate(alert)


@router.post("/alerts/{alert_id}/resolve")
async def resolve_alert(
    alert_id: str,
    resolved_by: str = Query(default="system"),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.resolved = True
    alert.resolved_at = datetime.now()
    alert.resolved_by = resolved_by
    await db.commit()
    return {"success": True, "message": "Alert resolved"}


@router.post("/alerts/bulk-resolve")
async def bulk_resolve_alerts(
    body: BulkResolveRequest = Body(...),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Alert).where(Alert.id.in_(body.alert_ids)))
    alerts = result.scalars().all()
    for alert in alerts:
        alert.resolved = True
        alert.resolved_at = datetime.now()
        alert.resolved_by = body.resolved_by
    await db.commit()
    return {"success": True, "resolved_count": len(alerts)}


# ── Packet Endpoints ─────────────────────────────────────────

@router.get("/packets", response_model=PacketListResponse)
async def list_packets(
    protocol: Optional[str] = None,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
    is_alert: Optional[bool] = None,
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    query = select(CapturedPacket).order_by(desc(CapturedPacket.timestamp))
    count_query = select(func.count(CapturedPacket.id))

    if protocol:
        query = query.where(CapturedPacket.protocol == protocol.upper())
        count_query = count_query.where(CapturedPacket.protocol == protocol.upper())
    if src_ip:
        query = query.where(CapturedPacket.src_ip == src_ip)
        count_query = count_query.where(CapturedPacket.src_ip == src_ip)
    if dst_ip:
        query = query.where(CapturedPacket.dst_ip == dst_ip)
        count_query = count_query.where(CapturedPacket.dst_ip == dst_ip)
    if src_port:
        query = query.where(CapturedPacket.src_port == src_port)
        count_query = count_query.where(CapturedPacket.src_port == src_port)
    if dst_port:
        query = query.where(CapturedPacket.dst_port == dst_port)
        count_query = count_query.where(CapturedPacket.dst_port == dst_port)
    if is_alert is not None:
        query = query.where(CapturedPacket.is_alert == is_alert)
        count_query = count_query.where(CapturedPacket.is_alert == is_alert)

    total = (await db.execute(count_query)).scalar() or 0
    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    packets = result.scalars().all()

    return PacketListResponse(
        total=total,
        packets=[PacketResponse.model_validate(p) for p in packets],
    )


@router.get("/packets/{packet_id}", response_model=PacketDetailResponse)
async def get_packet(packet_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(CapturedPacket).where(CapturedPacket.id == packet_id))
    packet = result.scalar_one_or_none()
    if not packet:
        raise HTTPException(status_code=404, detail="Packet not found")

    return PacketDetailResponse(
        success=True,
        packet=PacketResponse.model_validate(packet),
        hex_dump=packet.raw_hex,
    )


@router.get("/packets/stats/overview")
async def packet_stats(db: AsyncSession = Depends(get_db)):
    """Protocol distribution, top IPs, top ports."""
    proto_result = await db.execute(
        select(CapturedPacket.protocol, func.count(CapturedPacket.id))
        .group_by(CapturedPacket.protocol)
    )
    by_protocol = {p: c for p, c in proto_result.all()}

    src_result = await db.execute(
        select(CapturedPacket.src_ip, func.count(CapturedPacket.id))
        .group_by(CapturedPacket.src_ip)
        .order_by(func.count(CapturedPacket.id).desc())
        .limit(10)
    )
    top_sources = [{"ip": ip, "count": c} for ip, c in src_result.all()]

    dst_result = await db.execute(
        select(CapturedPacket.dst_ip, func.count(CapturedPacket.id))
        .group_by(CapturedPacket.dst_ip)
        .order_by(func.count(CapturedPacket.id).desc())
        .limit(10)
    )
    top_destinations = [{"ip": ip, "count": c} for ip, c in dst_result.all()]

    port_result = await db.execute(
        select(CapturedPacket.dst_port, func.count(CapturedPacket.id))
        .group_by(CapturedPacket.dst_port)
        .where(CapturedPacket.dst_port > 0)
        .order_by(func.count(CapturedPacket.id).desc())
        .limit(10)
    )
    top_ports = [{"port": p, "count": c} for p, c in port_result.all()]

    total = await db.scalar(select(func.count(CapturedPacket.id)))

    return {
        "success": True,
        "data": {
            "total_packets": total or 0,
            "by_protocol": by_protocol,
            "top_sources": top_sources,
            "top_destinations": top_destinations,
            "top_ports": top_ports,
        },
    }


# ── Stats Endpoints ─────────────────────────────────────────

@router.get("/stats/overview")
async def get_stats():
    live = alert_manager.get_live_stats()
    live["active_alerts"] = await alert_manager.get_active_alert_count()
    return {"success": True, "data": live}


@router.get("/stats/throughput")
async def get_throughput(
    minutes: int = Query(default=5, le=60),
    db: AsyncSession = Depends(get_db),
):
    since = datetime.now() - timedelta(minutes=minutes)
    result = await db.execute(
        select(TrafficStats)
        .where(TrafficStats.timestamp >= since)
        .order_by(TrafficStats.timestamp)
    )
    stats = result.scalars().all()

    series = [
        {
            "timestamp": s.timestamp.isoformat() if s.timestamp else "",
            "packets_per_second": s.packets_per_second,
            "bytes_per_second": s.bytes_per_second,
            "total_packets": s.total_packets,
            "active_alerts": s.active_alerts,
        }
        for s in stats
    ]

    if stats:
        pps_vals = [s.packets_per_second for s in stats]
        bps_vals = [s.bytes_per_second for s in stats]
        summary = {
            "avg_pps": round(sum(pps_vals) / len(pps_vals), 2),
            "peak_pps": max(pps_vals),
            "avg_bps": round(sum(bps_vals) / len(bps_vals), 2),
            "peak_bps": max(bps_vals),
        }
    else:
        summary = {"avg_pps": 0, "peak_pps": 0, "avg_bps": 0, "peak_bps": 0}

    return {"success": True, "series": series, "summary": summary}


@router.get("/stats/summary")
async def get_summary(db: AsyncSession = Depends(get_db)):
    severity_counts = {}
    for sev in ["critical", "high", "medium", "low"]:
        count = await db.scalar(
            select(func.count(Alert.id)).where(
                Alert.severity == sev, Alert.resolved == False
            )
        )
        severity_counts[sev] = count or 0

    category_counts = {}
    result = await db.execute(
        select(Alert.category, func.count(Alert.id))
        .where(Alert.resolved == False)
        .group_by(Alert.category)
    )
    for cat, cnt in result.all():
        category_counts[cat] = cnt

    method_counts = {}
    result = await db.execute(
        select(Alert.detection_method, func.count(Alert.id))
        .group_by(Alert.detection_method)
    )
    for method, cnt in result.all():
        method_counts[method] = cnt

    return {
        "success": True,
        "data": {
            "by_severity": severity_counts,
            "by_category": category_counts,
            "by_method": method_counts,
        },
    }


# ── Rules Endpoints ─────────────────────────────────────────

@router.get("/rules", response_model=list[RuleResponse])
async def list_rules(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(DetectionRule).order_by(DetectionRule.created_at))
    rules = result.scalars().all()
    return [RuleResponse.model_validate(r) for r in rules]


@router.post("/rules", response_model=RuleResponse)
async def create_rule(rule: RuleCreate, db: AsyncSession = Depends(get_db)):
    new_rule = DetectionRule(
        name=rule.name,
        rule_text=rule.rule_text,
        category=rule.category,
        severity=rule.severity,
    )
    db.add(new_rule)
    await db.commit()
    await db.refresh(new_rule)
    return RuleResponse.model_validate(new_rule)


@router.delete("/rules/{rule_id}")
async def delete_rule(rule_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(DetectionRule).where(DetectionRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    await db.delete(rule)
    await db.commit()
    return {"success": True}


