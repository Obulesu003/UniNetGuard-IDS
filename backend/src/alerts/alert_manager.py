"""Alert management and orchestration"""

import time
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Callable
from collections import deque
from threading import Lock
import logging

from ..utils.logger import get_logger
from ..utils.config import get_config
from .models import Alert, AlertSeverity, AlertChannel


logger = get_logger(__name__)


class RateLimiter:
    """Rate limiter to prevent alert floods"""
    def __init__(self, window_seconds: int = 300, max_alerts: int = 3):
        self.window_seconds = window_seconds
        self.max_alerts = max_alerts
        self.alerts: deque = deque()
        self._lock = Lock()

    def should_send(self, alert: Alert) -> bool:
        with self._lock:
            now = time.time()
            self.alerts = deque([(ts, aid) for ts, aid in self.alerts if now - ts < self.window_seconds])

            for ts, aid in self.alerts:
                if aid == alert.id:
                    return False

            if len(self.alerts) >= self.max_alerts:
                logger.debug(f"Alert rate limited: {alert.id}")
                return False

            self.alerts.append((now, alert.id))
            return True


class AlertManager:
    def __init__(self, config=None):
        self.config = config or get_config()
        self.alerts_config = self.config.alerts

        self._alert_history: deque = deque(maxlen=1000)
        self._rate_limiter = RateLimiter(window_seconds=300, max_alerts=3)
        self._callbacks: List[Callable] = []
        self._lock = Lock()

        logger.info("AlertManager initialized")

    def create_alert(self, attack_type: str, confidence: float, explanation: Dict[str, Any],
                    source_ip: Optional[str] = None, severity: AlertSeverity = AlertSeverity.HIGH) -> Optional[Alert]:
        alert = Alert.from_classification(attack_type, confidence, explanation, source_ip, severity)
        return self.send_alert(alert)

    def create_alerts_for_attacks(self, detected_attacks: List[str], stats: Dict[str, Any],
                                  classification: Dict[str, Any]) -> List[Optional[Alert]]:
        """Create alerts for all detected attacks"""
        alerts = []
        for attack in detected_attacks:
            severity = self._get_attack_severity(attack, stats)
            alert = self.create_alert(
                attack_type=attack,
                confidence=classification.get('confidence', 0.85),
                explanation={'summary': f'{attack} detected', 'stats': stats},
                source_ip=classification.get('source_ip', 'Multiple sources'),
                severity=severity
            )
            if alert:
                alerts.append(alert)
        return alerts

    def _get_attack_severity(self, attack_type: str, stats: Dict[str, Any]) -> AlertSeverity:
        """Determine severity based on attack type and count"""
        attack_counts = {
            'DoS': stats.get('dos_packets', 0),
            'Brute Force': stats.get('brute_force_count', 0),
            'SQL Injection': stats.get('sql_injection_count', 0),
            'XSS': stats.get('xss_count', 0),
            'Port Scan': len([k for k, v in stats.get('port_scan_sources', {}).items() if len(v) >= 15]),
            'Bot': 1 if stats.get('bot_beacon_score', 0) >= 3 else 0
        }

        count = attack_counts.get(attack_type, 0)

        if attack_type in ['DoS', 'Brute Force']:
            if count >= 100:
                return AlertSeverity.CRITICAL
            elif count >= 50:
                return AlertSeverity.HIGH
            elif count >= 30:
                return AlertSeverity.MEDIUM
            else:
                return AlertSeverity.LOW
        else:
            if count >= 50:
                return AlertSeverity.CRITICAL
            elif count >= 25:
                return AlertSeverity.HIGH
            elif count >= 15:
                return AlertSeverity.MEDIUM
            else:
                return AlertSeverity.LOW

    def send_alert(self, alert: Alert) -> Optional[Alert]:
        if not self._rate_limiter.should_send(alert):
            logger.debug(f"Alert rate limited: {alert.id}")
            return None

        with self._lock:
            self._alert_history.append(alert)

            for callback in self._callbacks:
                try:
                    callback(alert)
                except Exception as e:
                    logger.error(f"Alert callback error: {e}")

            return alert

    def get_alerts(self, limit: int = 100, severity: Optional[AlertSeverity] = None,
                   since: Optional[datetime] = None) -> List[Alert]:
        alerts = list(self._alert_history)
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        if since:
            alerts = [a for a in alerts if datetime.fromisoformat(a.timestamp) >= since]
        return alerts[-limit:]

    def get_alert_stats(self) -> Dict[str, Any]:
        alerts = list(self._alert_history)

        severity_counts = {s.name: 0 for s in AlertSeverity}
        for alert in alerts:
            severity_counts[alert.severity.name] += 1

        attack_counts = {}
        for alert in alerts:
            attack_counts[alert.attack_type] = attack_counts.get(alert.attack_type, 0) + 1

        return {
            'total_alerts': len(alerts),
            'by_severity': severity_counts,
            'by_attack_type': attack_counts,
            'last_alert': alerts[-1].timestamp if alerts else None
        }

    def register_callback(self, callback: Callable):
        self._callbacks.append(callback)

    def clear_alerts(self):
        with self._lock:
            self._alert_history.clear()
