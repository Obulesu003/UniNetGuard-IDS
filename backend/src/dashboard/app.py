"""Flask dashboard application with real-time Socket.IO updates"""

import os, json, threading, time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List
from flask import Flask, render_template, jsonify, request, Response, make_response
from flask_socketio import SocketIO, emit
import logging

from ..utils.logger import get_logger
from ..utils.config import get_config
from ..capture.packet_capture import PacketCapture, CapturedPacket
from ..capture.traffic_processor import TrafficProcessor, PacketStats
from ..ml.classifier import TrafficClassifier, ClassificationResult
from ..ml.features import FeatureExtractor
from ..ai.explanation_engine import ExplanationEngine, TrafficExplanation
from ..alerts.alert_manager import AlertManager, Alert

logger = get_logger(__name__)


class AppState:
    def __init__(self, socketio):
        self.socketio = socketio
        self.capture: Optional[PacketCapture] = None
        self.processor: Optional[TrafficProcessor] = None
        self.classifier: Optional[TrafficClassifier] = None
        self.explainer: Optional[ExplanationEngine] = None
        self.alert_manager: Optional[AlertManager] = None
        self.is_capturing = False
        self.current_stats: Dict[str, Any] = {}
        self.current_classification: Dict[str, Any] = {}
        self.current_explanation: Dict[str, Any] = {}
        self._lock = threading.Lock()
        self._stats_thread: Optional[threading.Thread] = None
        self._running = False
        self._initialize_components()

    def _initialize_components(self):
        try:
            self.capture = PacketCapture()
            self.processor = TrafficProcessor(window_size=60)
            self.classifier = TrafficClassifier()
            self.explainer = ExplanationEngine()
            self.alert_manager = AlertManager()
            self.alert_manager.register_callback(self._on_alert)
            logger.info("All components initialized")
        except Exception as e:
            logger.error(f"Failed to initialize components: {e}")

    def _on_alert(self, alert: Alert):
        try:
            self.socketio.emit('alert', alert.to_dict(), namespace='/')
            logger.info(f"Alert emitted: {alert.attack_type}")
        except Exception as e:
            logger.error(f"Error emitting alert: {e}")

    def _emit_update(self):
        try:
            with self._lock:
                stats = self.current_stats.copy() if self.current_stats else {}
                classification = self.current_classification.copy() if self.current_classification else {}
                explanation = self.current_explanation.copy() if self.current_explanation else {}
            self.socketio.emit('traffic_update', {
                'stats': stats, 'classification': classification, 'explanation': explanation,
                'timestamp': datetime.now().isoformat()
            }, namespace='/')
        except Exception as e:
            logger.error(f"Error emitting update: {e}")

    def _stats_loop(self):
        while self._running:
            if self.is_capturing and self.processor:
                self._emit_update()
            time.sleep(0.5)

    def _process_packet(self, packet: CapturedPacket):
        try:
            self.processor.add_packet(packet)
            features = self.processor.get_current_features()
            with self._lock:
                self.current_stats = self.processor.get_stats().to_dict()
            is_threat, classification = self.classifier.is_threat(features)
            with self._lock:
                self.current_classification = classification.to_dict()
            packet_dict = packet.to_dict()
            packet_dict['threat_label'] = classification.label
            packet_dict['confidence'] = classification.confidence
            packet_dict['threat_level'] = 'high' if classification.severity >= 3 else 'medium' if classification.severity >= 2 else 'low' if classification.severity >= 1 else 'none'
            if features.get('total_packets', 0) > 10:
                explanation = self.explainer.generate(features, classification.to_dict())
                with self._lock:
                    self.current_explanation = explanation.to_dict()
                if is_threat and classification.confidence > 0.85:
                    detected_attacks = classification.all_detected_attacks or [classification.category]
                    if detected_attacks:
                        self.alert_manager.create_alerts_for_attacks(detected_attacks=detected_attacks, stats=features, classification=classification.to_dict())
            self._emit_update()
        except Exception as e:
            logger.error(f"Error processing packet: {e}")

    def start_capture(self, interface: str = "auto", bpf_filter: str = ""):
        with self._lock:
            if self.is_capturing: return False
            try:
                logger.info(f"Starting capture on {interface}")
                self._running = True
                self._stats_thread = threading.Thread(target=self._stats_loop, daemon=True)
                self._stats_thread.start()
                self.capture.start_capture(interface=interface, bpf_filter=bpf_filter, callback=self._process_packet, simulate=True)
                self.is_capturing = True
                logger.info(f"Capture started on interface: {interface}"); return True
            except Exception as e:
                logger.error(f"Failed to start capture: {e}"); return False

    def stop_capture(self):
        with self._lock:
            if not self.is_capturing: return False
            self._running = False
            if self._stats_thread: self._stats_thread.join(timeout=1)
            self.capture.stop_capture()
            self.is_capturing = False
            logger.info("Capture stopped"); return True

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            return {'is_capturing': self.is_capturing, 'stats': self.current_stats,
                    'classification': self.current_classification, 'explanation': self.current_explanation,
                    'alert_stats': self.alert_manager.get_alert_stats() if self.alert_manager else {},
                    'timestamp': datetime.now().isoformat()}


_app_state: Optional[AppState] = None


def create_app(config_path: str = "config.yaml") -> Flask:
    global _app_state
    template_dir = Path(__file__).parent / 'templates'
    app = Flask(__name__, template_folder=str(template_dir))
    app.config['SECRET_KEY'] = 'netwatcher-secret-key'
    app.config['JSON_SORT_KEYS'] = False
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading', logger=False, engineio_logger=False)

    @app.route('/')
    def index():
        response = make_response(render_template('index.html'))
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'; response.headers['Expires'] = '0'
        return response

    @app.route('/api/status')
    def get_status(): return jsonify(_app_state.get_status())

    @app.route('/api/capture/start', methods=['POST'])
    def start_capture():
        data = request.get_json() or {}
        success = _app_state.start_capture(data.get('interface', 'auto'), data.get('filter', ''))
        return jsonify({'success': success, 'message': 'Capture started' if success else 'Failed'})

    @app.route('/api/capture/stop', methods=['POST'])
    def stop_capture():
        success = _app_state.stop_capture()
        return jsonify({'success': success, 'message': 'Capture stopped' if success else 'Was not running'})

    @app.route('/api/traffic/stats')
    def traffic_stats():
        with _app_state._lock: return jsonify(_app_state.current_stats)

    @app.route('/api/traffic/packets')
    def recent_packets():
        count = request.args.get('count', 100, type=int)
        packets = _app_state.processor.get_recent_packets(count)
        with _app_state._lock: current_class = _app_state.current_classification
        for pkt in packets:
            pkt['threat_label'] = current_class.get('label', 'Normal') if current_class else 'Normal'
            pkt['confidence'] = current_class.get('confidence', 0) if current_class else 0
            pkt['threat_level'] = current_class.get('threat_level', 'none') if current_class else 'none'
        return jsonify(packets)

    @app.route('/api/alerts')
    def get_alerts():
        limit = request.args.get('limit', 50, type=int)
        alerts = _app_state.alert_manager.get_alerts(limit)
        return jsonify([a.to_dict() for a in alerts])

    @app.route('/api/alerts/stats')
    def alert_stats(): return jsonify(_app_state.alert_manager.get_alert_stats())

    @app.route('/api/alerts/clear', methods=['POST'])
    def clear_alerts():
        _app_state.alert_manager.clear_alerts()
        return jsonify({'success': True})

    @app.route('/api/interfaces')
    def get_interfaces():
        interfaces = _app_state.capture.get_available_interfaces()
        return jsonify(interfaces)

    @socketio.on('connect')
    def handle_connect():
        logger.info('Client connected'); emit('status', _app_state.get_status())

    @socketio.on('disconnect')
    def handle_disconnect(): logger.info('Client disconnected')

    @socketio.on('request_update')
    def handle_update_request(): emit('status', _app_state.get_status())

    _app_state = AppState(socketio)
    return app, socketio


def get_app_state() -> Optional[AppState]: return _app_state
