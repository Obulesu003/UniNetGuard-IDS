#!/bin/bash
# ─── UniNetGuard IDS ─ Quick Start ───────────────────────────

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}═══════════════════════════════════════════════${NC}"
echo -e "${BLUE}  UniNetGuard IDS - Quick Start${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════${NC}"

# Detect OS
OS="$(uname -s)"
BACKEND_DIR="$(dirname "$0")/backend"
FRONTEND_DIR="$(dirname "$0")/frontend"

start_backend() {
    echo -e "\n${GREEN}[1/3] Starting Backend (FastAPI + Scapy)...${NC}"
    cd "$BACKEND_DIR" || exit 1

    if [ ! -d "venv" ]; then
        echo "Creating virtual environment..."
        python3 -m venv venv
    fi

    source venv/bin/activate
    pip install -q -r requirements.txt 2>/dev/null

    echo "Starting backend on http://localhost:8000"
    echo "API docs at http://localhost:8000/docs"
    python -m uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload
}

start_frontend() {
    echo -e "\n${GREEN}[2/3] Starting Frontend (React)...${NC}"
    cd "$FRONTEND_DIR" || exit 1

    if [ ! -d "node_modules" ]; then
        echo "Installing dependencies..."
        npm install
    fi

    echo "Starting frontend on http://localhost:5173"
    npm run dev
}

docker_mode() {
    echo -e "\n${GREEN}Starting with Docker Compose...${NC}"
    docker compose up --build
}

case "$1" in
    docker)
        docker_mode
        ;;
    backend)
        start_backend
        ;;
    frontend)
        start_frontend
        ;;
    all|"")
        start_backend &
        BACKEND_PID=$!
        sleep 3
        start_frontend
        kill $BACKEND_PID 2>/dev/null
        ;;
    *)
        echo "Usage: $0 {all|backend|frontend|docker}"
        ;;
esac
