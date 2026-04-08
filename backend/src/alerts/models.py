"""Alert data structures"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any
from enum import Enum


class AlertSeverity(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class AlertChannel(Enum):
    EMAIL = "email"
    SMS = "sms"
    SLACK = "slack"


@dataclass
class Alert:
    id: str
    timestamp: str
    severity: AlertSeverity
    title: str
    message: str
    attack_type: str
    confidence: float
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    ports: List[int] = field(default_factory=list)
    channels_sent: List[AlertChannel] = field(default_factory=list)
    explanation: Optional[str] = None
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'timestamp': self.timestamp,
            'severity': self.severity.name,
            'severity_level': self.severity.value,
            'title': self.title,
            'message': self.message,
            'attack_type': self.attack_type,
            'confidence': round(self.confidence, 4),
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'ports': self.ports,
            'channels_sent': [c.value for c in self.channels_sent],
            'explanation': self.explanation,
            'recommendations': self.recommendations
        }

    @classmethod
    def from_classification(cls, attack_type: str, confidence: float, explanation: Dict[str, Any],
                           source_ip: Optional[str] = None, severity: Optional[AlertSeverity] = None) -> 'Alert':
        import uuid

        severity_map = {
            'Normal': AlertSeverity.LOW,
            'Reconnaissance': AlertSeverity.MEDIUM,
            'Web Attack': AlertSeverity.HIGH,
            'Brute Force': AlertSeverity.HIGH,
            'DoS': AlertSeverity.CRITICAL,
            'Botnet': AlertSeverity.CRITICAL,
            'Infiltration': AlertSeverity.CRITICAL,
            'Vulnerability': AlertSeverity.CRITICAL
        }

        if severity is None:
            severity = severity_map.get(attack_type, AlertSeverity.HIGH)
        title = f"[{severity.name}] {attack_type} Detected"
        message = f"{attack_type} activity detected with {confidence*100:.1f}% confidence"

        if explanation:
            message += f"\n\n{explanation.get('summary', '')}"

        return cls(
            id=str(uuid.uuid4())[:8],
            timestamp=datetime.now().isoformat(),
            severity=severity,
            title=title,
            message=message,
            attack_type=attack_type,
            confidence=confidence,
            source_ip=source_ip,
            explanation=explanation.get('ai_explanation'),
            recommendations=explanation.get('recommendations', [])
        )
