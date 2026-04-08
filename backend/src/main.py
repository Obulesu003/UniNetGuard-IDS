import asyncio
import random
import time
import threading
from datetime import datetime
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession
from sse_starlette.sse import EventSourceResponse

from src.models import init_db, get_db, Alert, CapturedPacket


# ── Global State ─────────────────────────────────────────────
class IDSState:
    def __init__(self):
        self.is_capturing = False
        self.capture_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.total_packets = 0
        self.total_bytes = 0
        self.tcp_count = 0
        self.udp_count = 0
        self.icmp_count = 0
        self.pps = 0
        self.bps = 0
        self._lock = threading.Lock()

    def reset(self):
        with self._lock:
            self.total_packets = 0
            self.total_bytes = 0
            self.tcp_count = 0
            self.udp_count = 0
            self.icmp_count = 0
            self.pps = 0
            self.bps = 0


state = IDSState()


# ── Synthetic Traffic Generator ───────────────────────────────
SYNTHETIC_IPS = [
    "192.168.1.100", "10.0.0.50", "172.16.0.20", "8.8.8.8", "1.1.1.1",
    "142.250.185.78", "54.239.28.85", "157.240.1.35"
]
COMMON_PORTS = [80, 443, 53, 22, 8080, 3306, 6379, 445]


def generate_packet():
    """Generate a synthetic packet."""
    src_ip = random.choice(SYNTHETIC_IPS)
    dst_ip = random.choice([ip for ip in SYNTHETIC_IPS if ip != src_ip])
    protocol = random.choice(["TCP", "TCP", "TCP", "UDP"])
    src_port = random.randint(1024, 65535)
    dst_port = random.choice(COMMON_PORTS)
    length = random.randint(40, 1500)
    flags = random.choice(["S", "A", "PA", "F", ""])

    is_attack = random.random() < 0.02  # 2% chance of attack

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "length": length,
        "tcp_flags": flags,
        "is_attack": is_attack,
    }


async def capture_loop():
    """Background loop that generates and stores synthetic packets."""
    last_time = time.time()
    last_count = 0

    while not state.stop_event.is_set():
        # Generate packet
        pkt = generate_packet()

        # Update counters
        with state._lock:
            state.total_packets += 1
            state.total_bytes += pkt["length"]
            if pkt["protocol"] == "TCP":
                state.tcp_count += 1
            elif pkt["protocol"] == "UDP":
                state.udp_count += 1
            else:
                state.icmp_count += 1

            # Calculate PPS/BPS
            now = time.time()
            elapsed = now - last_time
            if elapsed >= 1.0:
                state.pps = round((state.total_packets - last_count) / elapsed)
                state.bps = round((state.total_bytes - (state.total_bytes - sum([p.get("length", 0) for _ in range(int(state.pps))]))) / elapsed) if elapsed > 0 else 0
                last_time = now
                last_count = state.total_packets

        # Store packet in DB
        from src.models import async_session
        async with async_session() as session:
            packet = CapturedPacket(
                timestamp=datetime.now(),
                src_ip=pkt["src_ip"],
                dst_ip=pkt["dst_ip"],
                src_port=pkt["src_port"],
                dst_port=pkt["dst_port"],
                protocol=pkt["protocol"],
                length=pkt["length"],
                tcp_flags=pkt["tcp_flags"],
                is_alert=pkt["is_attack"],
            )
            session.add(packet)

            # Generate alert if attack
            if pkt["is_attack"]:
                alert = Alert(
                    timestamp=datetime.now(),
                    severity="high",
                    category="suspicious_traffic",
                    title="Suspicious Traffic Detected",
                    description=f"TCP flags: {pkt['tcp_flags']} from {pkt['src_ip']}",
                    source_ip=pkt["src_ip"],
                    dest_ip=pkt["dst_ip"],
                    source_port=pkt["src_port"],
                    dest_port=pkt["dst_port"],
                    protocol=pkt["protocol"],
                    signature_id="SYN-001",
                    detection_method="anomaly",
                )
                session.add(alert)

            await session.commit()

        await asyncio.sleep(0.1)  # ~10 packets/sec


# ── FastAPI App ─────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield
    state.stop_event.set()


app = FastAPI(title="UniNetGuard IDS", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Capture Endpoints ────────────────────────────────────────
@app.post("/api/capture/start")
async def start_capture():
    if state.is_capturing:
        return {"success": True, "message": "Capture already running"}

    state.is_capturing = True
    state.stop_event.clear()
    asyncio.create_task(capture_loop())

    return {"success": True, "message": "Capture started"}


@app.post("/api/capture/stop")
async def stop_capture():
    state.is_capturing = False
    state.stop_event.set()
    state.reset()
    return {"success": True, "message": "Capture stopped"}


@app.get("/api/capture/status")
async def capture_status():
    return {
        "success": True,
        "data": {
            "is_running": state.is_capturing,
            "total_packets": state.total_packets,
            "total_bytes": state.total_bytes,
            "packets_per_second": state.pps,
            "bytes_per_second": state.bps,
        }
    }


# ── Stats Endpoints ──────────────────────────────────────────
@app.get("/api/stats/overview")
async def stats_overview(db: AsyncSession = Depends(get_db)):
    # Get counts from DB
    total_packets = await db.scalar(select(func.count(CapturedPacket.id))) or 0
    total_bytes = await db.scalar(select(func.sum(CapturedPacket.length))) or 0

    proto_result = await db.execute(
        select(CapturedPacket.protocol, func.count(CapturedPacket.id))
        .group_by(CapturedPacket.protocol)
    )
    protocols = {"tcp": 0, "udp": 0, "icmp": 0, "other": 0}
    for proto, count in proto_result.all():
        key = proto.lower()
        if key in protocols:
            protocols[key] = count
        else:
            protocols["other"] += count

    active_alerts = await db.scalar(
        select(func.count(Alert.id)).where(Alert.resolved == False)
    ) or 0

    return {
        "success": True,
        "data": {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "packets_per_second": state.pps,
            "bytes_per_second": state.bps,
            "protocols": protocols,
            "active_alerts": active_alerts,
        }
    }


@app.get("/api/stats/throughput")
async def stats_throughput(db: AsyncSession = Depends(get_db)):
    # Return recent packets as throughput data points
    result = await db.execute(
        select(CapturedPacket.timestamp, func.count(CapturedPacket.id), func.sum(CapturedPacket.length))
        .group_by(func.round(func.julianday(CapturedPacket.timestamp) * 288))  # Group by 5-min windows
        .order_by(CapturedPacket.timestamp.desc())
        .limit(30)
    )
    rows = result.all()

    series = []
    for ts, count, length in rows:
        series.append({
            "timestamp": ts.isoformat() if ts else "",
            "packets_per_second": count,
            "bytes_per_second": length or 0,
            "total_packets": count,
            "active_alerts": 0,
        })

    return {"success": True, "series": series, "summary": {"avg_pps": 0, "peak_pps": 0, "avg_bps": 0, "peak_bps": 0}}


@app.get("/api/stats/summary")
async def stats_summary(db: AsyncSession = Depends(get_db)):
    # Get ALL alerts (not just unresolved)
    severity_counts = {}
    for sev in ["critical", "high", "medium", "low"]:
        count = await db.scalar(
            select(func.count(Alert.id)).where(Alert.severity == sev)
        )
        severity_counts[sev] = count or 0

    category_result = await db.execute(
        select(Alert.category, func.count(Alert.id))
        .group_by(Alert.category)
    )
    category_counts = {cat: cnt for cat, cnt in category_result.all()}

    method_result = await db.execute(
        select(Alert.detection_method, func.count(Alert.id))
        .group_by(Alert.detection_method)
    )
    method_counts = {m: cnt for m, cnt in method_result.all()}

    return {
        "success": True,
        "data": {
            "by_severity": severity_counts,
            "by_category": category_counts,
            "by_method": method_counts,
        }
    }


# ── Alert Endpoints ──────────────────────────────────────────
@app.get("/api/alerts")
async def list_alerts(
    limit: int = Query(default=50, le=500),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    total = await db.scalar(select(func.count(Alert.id))) or 0
    result = await db.execute(
        select(Alert).order_by(desc(Alert.timestamp)).offset(offset).limit(limit)
    )
    alerts = result.scalars().all()

    return {
        "success": True,
        "total": total,
        "alerts": [
            {
                "id": a.id,
                "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                "severity": a.severity,
                "category": a.category,
                "title": a.title,
                "description": a.description or "",
                "source_ip": a.source_ip,
                "dest_ip": a.dest_ip or "",
                "source_port": a.source_port or 0,
                "dest_port": a.dest_port or 0,
                "protocol": a.protocol or "unknown",
                "signature_id": a.signature_id or "",
                "detection_method": a.detection_method,
                "resolved": a.resolved,
                "resolved_at": a.resolved_at.isoformat() if a.resolved_at else None,
                "resolved_by": a.resolved_by,
            }
            for a in alerts
        ]
    }


@app.post("/api/alerts/{alert_id}/resolve")
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


# ── Packet Endpoints ─────────────────────────────────────────
@app.get("/api/packets")
async def list_packets(
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
    protocol: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    query = select(CapturedPacket).order_by(desc(CapturedPacket.timestamp))
    count_query = select(func.count(CapturedPacket.id))

    if protocol:
        query = query.where(CapturedPacket.protocol == protocol.upper())
        count_query = count_query.where(CapturedPacket.protocol == protocol.upper())

    total = await db.scalar(count_query) or 0
    result = await db.execute(query.offset(offset).limit(limit))
    packets = result.scalars().all()

    return {
        "success": True,
        "total": total,
        "packets": [
            {
                "id": p.id,
                "timestamp": p.timestamp.isoformat() if p.timestamp else None,
                "src_ip": p.src_ip,
                "dst_ip": p.dst_ip,
                "src_port": p.src_port or 0,
                "dst_port": p.dst_port or 0,
                "protocol": p.protocol,
                "length": p.length,
                "ttl": p.ttl,
                "tcp_flags": p.tcp_flags or "",
                "is_alert": p.is_alert,
            }
            for p in packets
        ]
    }


@app.get("/api/packets/stats")
async def packet_stats(db: AsyncSession = Depends(get_db)):
    total = await db.scalar(select(func.count(CapturedPacket.id))) or 0

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

    return {
        "success": True,
        "data": {
            "total_packets": total,
            "by_protocol": by_protocol,
            "top_sources": top_sources,
            "top_destinations": top_destinations,
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
