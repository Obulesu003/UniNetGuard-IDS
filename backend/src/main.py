import asyncio
import socketio
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from src.core.database import init_db
from src.core.alert_manager import alert_manager
from src.capture.packet_capture import PacketCapture
from src.capture.synthetic import SyntheticTrafficGenerator
from src.capture.attack_simulator import AttackSimulator


# ── Global instances ────────────────────────────────────────

capture_engine = PacketCapture()
synth_engine: SyntheticTrafficGenerator = None
attack_engine: AttackSimulator = None
_main_loop: asyncio.AbstractEventLoop = None


# ── Socket.IO Server ────────────────────────────────────────

sio = socketio.AsyncServer(async_mode="asgi", cors_allowed_origins="*")


@sio.on("connect")
async def connect(sid, environ):
    await sio.emit("connected", {"sid": sid})


@sio.on("disconnect")
async def disconnect(sid):
    pass


@sio.on("subscribe")
async def handle_subscribe(sid, data):
    channel = data.get("channel") if data else None
    if channel:
        await sio.enter_room(sid, channel)


async def notify_alert(alert_data: dict):
    await sio.emit("alert", alert_data, room="alerts")


async def notify_stats(stats_data: dict):
    await sio.emit("stats", stats_data, room="stats")


alert_manager.subscribe(notify_alert)


# ── Background capture worker ────────────────────────────────

async def capture_worker(interface: str, bpf_filter: str):
    def sync_analyze(packet_info):
        asyncio.create_task(alert_manager.analyze_packet(packet_info))

    capture_engine.set_callback(sync_analyze)
    capture_engine.start(interface=interface, bpf_filter=bpf_filter)

    while capture_engine.is_running:
        await asyncio.sleep(2)
        stats = alert_manager.get_live_stats()
        stats["active_alerts"] = await alert_manager.get_active_alert_count()
        await notify_stats(stats)

    capture_engine.stop()


# ── FastAPI App ─────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    global _main_loop
    _main_loop = asyncio.get_running_loop()
    yield
    capture_engine.stop()
    global synth_engine, attack_engine
    if synth_engine:
        synth_engine.stop()
    if attack_engine:
        attack_engine.stop()


app = FastAPI(
    title="UniNetGuard IDS API",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Capture Control Endpoints (must be before router) ────────

@app.post("/api/capture/start")
async def start_capture(body: dict):
    global synth_engine
    interface = body.get("interface", "lo")
    bpf_filter = body.get("bpf_filter", "")
    pps = body.get("synthetic_pps", 0)

    if capture_engine.is_running:
        return {"success": False, "message": "Capture already running"}
    if synth_engine and synth_engine.is_running:
        return {"success": False, "message": "Synthetic traffic already running"}

    if pps > 0:
        synth_engine = SyntheticTrafficGenerator(
            callback=lambda pkt: _main_loop.create_task(alert_manager.analyze_packet(pkt)),
            packets_per_second=pps,
        )
        synth_engine.start()
        return {"success": True, "message": f"Synthetic traffic started at {pps} packets/sec", "mode": "synthetic"}

    asyncio.create_task(capture_worker(interface, bpf_filter))
    return {"success": True, "message": f"Capture started on {interface}", "mode": "live"}


@app.post("/api/capture/attack-sim")
async def start_attack_sim(body: dict):
    """Start attack simulation — sends real Scapy packets on the live interface.

    Sends realistic attack traffic (port scans, SYN floods, ICMP floods) that
    is captured by the live packet capture engine and analyzed for detection.
    This exercises the full pipeline: send → capture → analyze → alert.
    """
    global attack_engine
    interface = body.get("interface", "")
    if capture_engine.is_running:
        return {"success": False, "message": "Stop live capture first"}
    if attack_engine and attack_engine.is_running:
        return {"success": False, "message": "Attack simulation already running"}

    # Start live capture on the same interface
    asyncio.create_task(capture_worker(interface, ""))

    # Start attack simulator sending real packets
    attack_engine = AttackSimulator(
        callback=lambda pkt: _main_loop.create_task(alert_manager.analyze_packet(pkt)),
        interface=interface or None,
    )
    attack_engine.start()

    return {"success": True, "message": "Attack simulation started", "mode": "attack_sim"}


@app.post("/api/capture/stop")
async def stop_capture():
    global synth_engine, attack_engine
    # Reset stats when stopping (but keep alerts for historical record)
    alert_manager.reset_stats()
    if synth_engine and synth_engine.is_running:
        synth_engine.stop()
        return {"success": True, "message": "Synthetic traffic stopped"}
    if attack_engine and attack_engine.is_running:
        attack_engine.stop()
        return {"success": True, "message": "Attack simulation stopped"}
    if not capture_engine.is_running:
        return {"success": True, "message": "Capture not running"}
    capture_engine.stop()
    return {"success": True, "message": "Capture stopped"}


@app.get("/api/capture/interfaces")
async def list_interfaces():
    interfaces = capture_engine.get_interfaces()
    return {"success": True, "interfaces": interfaces}


@app.get("/api/capture/status")
async def capture_status():
    global synth_engine, attack_engine
    if attack_engine and attack_engine.is_running:
        live = alert_manager.get_live_stats()
        return {
            "success": True,
            "data": {
                "is_running": True,
                "interface": "Attack Simulation",
                "mode": "attack_sim",
                "total_packets": live["total_packets"],
                "total_bytes": live["total_bytes"],
                "packets_per_second": live["packets_per_second"],
                "bytes_per_second": live["bytes_per_second"],
                "active_alerts": await alert_manager.get_active_alert_count(),
            },
        }
    if synth_engine and synth_engine.is_running:
        live = alert_manager.get_live_stats()
        return {
            "success": True,
            "data": {
                "is_running": True,
                "interface": "synthetic",
                "mode": "synthetic",
                "total_packets": live["total_packets"],
                "total_bytes": live["total_bytes"],
                "packets_per_second": live["packets_per_second"],
                "bytes_per_second": live["bytes_per_second"],
                "active_alerts": await alert_manager.get_active_alert_count(),
            },
        }
    if capture_engine.is_running:
        stats = capture_engine.get_stats()
        stats["active_alerts"] = await alert_manager.get_active_alert_count()
        return {"success": True, "data": stats}
    return {
        "success": True,
        "data": {
            "is_running": False,
            "interface": None,
            "total_packets": 0,
            "total_bytes": 0,
            "packets_per_second": 0,
            "bytes_per_second": 0,
            "buffer_size": 0,
            "active_alerts": 0,
        },
    }


# ── API Routes (must be after capture endpoints) ───────────

from src.api.routes import router as api_router
app.include_router(api_router, prefix="/api")


# ── Mount Socket.IO ─────────────────────────────────────────

socket_app = socketio.ASGIApp(sio, app)
app = socket_app


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("src.main:app", host="0.0.0.0", port=8000, reload=True)
