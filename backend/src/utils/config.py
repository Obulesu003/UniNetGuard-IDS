"""Configuration management for Netwatcher"""

import os
import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field


@dataclass
class CaptureConfig:
    interface: str = "auto"
    filter: str = ""
    buffer_size: int = 10000
    output_dir: str = "./data/captured"


@dataclass
class MLConfig:
    model_path: str = "./models/traffic_classifier.pkl"
    confidence_threshold: float = 0.85
    training_data: str = "./data/cicids2017_sample.csv"


@dataclass
class AIConfig:
    provider: str = "openai"
    api_key: str = ""
    model: str = "gpt-3.5-turbo"
    explanation_level: str = "detailed"


@dataclass
class EmailConfig:
    enabled: bool = False
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    username: str = ""
    password: str = ""
    recipients: List[str] = field(default_factory=list)


@dataclass
class SMSConfig:
    enabled: bool = False
    twilio_sid: str = ""
    twilio_token: str = ""
    from_number: str = ""
    to_numbers: List[str] = field(default_factory=list)


@dataclass
class SlackConfig:
    enabled: bool = False
    webhook_url: str = ""


@dataclass
class AlertsConfig:
    email: EmailConfig = field(default_factory=EmailConfig)
    sms: SMSConfig = field(default_factory=SMSConfig)
    slack: SlackConfig = field(default_factory=SlackConfig)


@dataclass
class DashboardConfig:
    host: str = "0.0.0.0"
    port: int = 5000
    refresh_interval: int = 5


@dataclass
class ExportConfig:
    csv_dir: str = "./data/exports"
    pdf_dir: str = "./data/reports"


class Config:
    """Main configuration class for Netwatcher"""

    _instance: Optional['Config'] = None

    def __new__(cls, config_path: str = "config.yaml"):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, config_path: str = "config.yaml"):
        if self._initialized:
            return

        self.config_path = Path(config_path)
        self._load_config()
        self._initialized = True

    def _load_config(self):
        """Load configuration from YAML file"""
        if not self.config_path.exists():
            self._create_default_config()

        with open(self.config_path, 'r') as f:
            data = yaml.safe_load(f) or {}

        self.capture = CaptureConfig(**data.get('capture', {}))
        self.ml = MLConfig(**data.get('ml', {}))
        self.ai = AIConfig(
            api_key=os.environ.get('OPENAI_API_KEY', data.get('ai', {}).get('api_key', '')),
            **{k: v for k, v in data.get('ai', {}).items() if k != 'api_key'}
        )

        alerts_data = data.get('alerts', {})
        self.alerts = AlertsConfig(
            email=EmailConfig(**alerts_data.get('email', {})),
            sms=SMSConfig(**alerts_data.get('sms', {})),
            slack=SlackConfig(**alerts_data.get('slack', {}))
        )

        self.dashboard = DashboardConfig(**data.get('dashboard', {}))
        self.export = ExportConfig(**data.get('export', {}))

    def _create_default_config(self):
        """Create default configuration file"""
        default_config = {
            'capture': {
                'interface': 'auto',
                'filter': '',
                'buffer_size': 10000,
                'output_dir': './data/captured'
            },
            'ml': {
                'model_path': './models/traffic_classifier.pkl',
                'confidence_threshold': 0.85,
                'training_data': './data/cicids2017_sample.csv'
            },
            'ai': {
                'provider': 'openai',
                'api_key': '',
                'model': 'gpt-3.5-turbo',
                'explanation_level': 'detailed'
            },
            'alerts': {
                'email': {'enabled': False, 'smtp_host': '', 'smtp_port': 587, 'username': '', 'password': '', 'recipients': []},
                'sms': {'enabled': False, 'twilio_sid': '', 'twilio_token': '', 'from_number': '', 'to_numbers': []},
                'slack': {'enabled': False, 'webhook_url': ''}
            },
            'dashboard': {
                'host': '0.0.0.0',
                'port': 5000,
                'refresh_interval': 5
            },
            'export': {
                'csv_dir': './data/exports',
                'pdf_dir': './data/reports'
            }
        }

        os.makedirs(self.config_path.parent, exist_ok=True)
        with open(self.config_path, 'w') as f:
            yaml.dump(default_config, f, default_flow_style=False)

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by dot-notation key"""
        parts = key.split('.')
        obj = self
        for part in parts:
            if hasattr(obj, part):
                obj = getattr(obj, part)
            else:
                return default
        return obj


def get_config(config_path: str = "config.yaml") -> Config:
    """Get or create configuration instance"""
    return Config(config_path)
