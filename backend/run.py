"""Netwatcher IDS - Run script"""
import os, sys

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.dashboard.app import create_app
from src.utils.logger import setup_logger
from src.utils.config import get_config

if __name__ == '__main__':
    setup_logger()
    config = get_config()
    app, socketio = create_app()
    print(f"[+] Netwatcher IDS starting on http://{config.dashboard.host}:{config.dashboard.port}")
    print(f"[+] Dashboard: http://localhost:{config.dashboard.port}")
    socketio.run(app, host=config.dashboard.host, port=config.dashboard.port, debug=False, allow_unsafe_werkzeug=True)
