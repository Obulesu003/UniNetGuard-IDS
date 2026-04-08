# UniNetGuard IDS

A lightweight Intrusion Detection System with live packet capture and a web dashboard.

## Quick Start

### Option 1: Python (no Docker)

```bash
# Install dependencies
pip install -r backend/requirements.txt

# Start backend
cd backend
python -m uvicorn src.main:app --port 8000

# In another terminal, start frontend
cd frontend
npm install
npm run dev
```

Open http://localhost:5173

### Option 2: Docker Compose

```bash
docker compose up --build
```

Open http://localhost:3000

## Features

- **Live Packet Capture** — Scapy-based capture on any network interface
- **Signature Detection** — Pattern matching for common attack signatures
- **Anomaly Detection** — Port scan and flood detection
- **Real-time Dashboard** — WebSocket-powered live updates
- **Alert Management** — Resolve, filter, and track alerts

## Architecture

```
Backend: FastAPI + Scapy + SQLite
Frontend: React + Vite + Tailwind + Recharts
Real-time: Socket.IO
Storage: SQLite (alerts, stats, rules)
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/alerts | List alerts |
| POST | /api/alerts/{id}/resolve | Resolve alert |
| GET | /api/stats/overview | Live statistics |
| GET | /api/stats/throughput | Historical throughput |
| POST | /api/capture/start | Start capture |
| POST | /api/capture/stop | Stop capture |
| WS | /socket.io | Real-time events |

## Network Interface

By default runs on `lo` (loopback) for testing. To capture real traffic:

```bash
# List interfaces
curl http://localhost:8000/api/capture/interfaces

# Start on real interface (requires root/admin)
curl -X POST http://localhost:8000/api/capture/start \
  -H "Content-Type: application/json" \
  -d '{"interface": "eth0", "bpf_filter": "tcp"}'
```

## Detection Rules

- TCP SYN/NULL/Xmas scan detection
- Port scan detection (anomaly-based)
- Traffic flood detection
- Protocol classification (HTTP, HTTPS, DNS, SSH, SMB, MySQL, Redis)
