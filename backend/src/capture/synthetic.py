"""Synthetic traffic generator for testing the IDS."""
import random
import time
import threading
from datetime import datetime
from src.capture.packet_capture import PacketInfo


SYNTHETIC_IPS = [
    ("192.168.1.100", 54321), ("10.0.0.50", 12345), ("172.16.0.20", 44444),
    ("192.168.1.105", 22222), ("10.0.0.15", 33333), ("8.8.8.8", 53),
    ("1.1.1.1", 53), ("208.67.222.222", 53), ("151.101.1.69", 443),
    ("104.16.85.20", 443), ("142.250.185.78", 443), ("157.240.1.35", 443),
    ("31.13.69.228", 443), ("52.94.236.248", 443), ("54.239.28.85", 443),
]

COMMON_PORTS = [
    (80, "HTTP", "TCP"), (443, "HTTPS", "TCP"), (53, "DNS", "UDP"),
    (22, "SSH", "TCP"), (21, "FTP", "TCP"), (25, "SMTP", "TCP"),
    (3306, "MySQL", "TCP"), (5432, "PostgreSQL", "TCP"), (6379, "Redis", "TCP"),
    (8080, "HTTP-Alt", "TCP"), (445, "SMB", "TCP"), (3389, "RDP", "TCP"),
    (123, "NTP", "UDP"), (67, "DHCP", "UDP"), (1900, "SSDP", "UDP"),
]

DNS_QUERIES = [
    "google.com", "facebook.com", "twitter.com", "github.com",
    "stackoverflow.com", "youtube.com", "netflix.com", "reddit.com",
    "amazon.com", "cloudflare.com", "microsoft.com", "apple.com",
]

HTTP_METHODS = ["GET", "POST", "PUT", "HEAD", "OPTIONS"]


def generate_synthetic_packet() -> PacketInfo:
    """Generate a realistic-looking synthetic packet."""
    src_ip, src_port = random.choice(SYNTHETIC_IPS)
    port_info = random.choice(COMMON_PORTS)
    dst_port, service, protocol = port_info

    # Pick destination IP based on service
    if service == "DNS":
        dst_ip = "8.8.8.8"
    elif service in ("HTTP", "HTTPS"):
        https = random.random() > 0.3
        dst_ip = random.choice(["142.250.185.78", "151.101.1.69", "104.16.85.20", "157.240.1.35"])
        dst_port = 443 if https else 80
    else:
        dst_ip = random.choice([ip for ip, _ in SYNTHETIC_IPS if ip != src_ip])

    # Vary source port for realism
    src_port = random.randint(1024, 65535)

    length = random.randint(40, 1500)
    flags = ""

    if protocol == "TCP":
        # Normal traffic only — no attack flag injection
        # Use realistic flag distributions to avoid false positives
        if service in ("HTTP", "HTTPS"):
            flags = "PA"
        else:
            flags = random.choices(
                ["S", "A", "PA", "FA", "F"],
                weights=[20, 45, 25, 5, 5],
                k=1
            )[0]

    # Generate HTTP method for web traffic
    http_method = ""
    payload_preview = b""
    dns_query = ""

    if service == "DNS":
        dns_query = random.choice(DNS_QUERIES)
        payload = dns_query.encode()
        payload_preview = payload[:50]
    elif service in ("HTTP", "HTTP-Alt"):
        method = random.choice(HTTP_METHODS)
        http_method = method
        paths = ["/", "/index.html", "/api/users", "/login", "/search", "/static/app.js", "/assets/logo.png"]
        path = random.choice(paths)
        payload = f"{method} {path} HTTP/1.1\r\nHost: example.com\r\n\r\n".encode()
        payload_preview = payload[:80]
    elif service == "SSH":
        payload = b"SSH-2.0-OpenSSH_8.2\r\n"
        payload_preview = payload

    return PacketInfo(
        timestamp=datetime.now(),
        raw_data=b"",
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        length=length,
        flags=flags,
        payload_preview=payload_preview,
        ttl=random.choice([64, 128, 255]),
        ip_length=length,
        tcp_flags_int=0,
        tcp_seq=random.randint(1000, 999999999),
        tcp_ack=random.randint(1000, 999999999) if "A" in flags else 0,
        window_size=random.choice([8192, 65535, 29200, 16384, 32768]),
        checksum=0,
        dns_query=dns_query,
        http_method=http_method,
    )


class SyntheticTrafficGenerator:
    """Generates synthetic network traffic for testing."""

    def __init__(self, callback, packets_per_second: int = 10):
        self.callback = callback
        self.packets_per_second = packets_per_second
        self.is_running = False
        self.thread: threading.Thread = None

    def start(self):
        if self.is_running:
            return
        self.is_running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def stop(self):
        self.is_running = False
        if self.thread:
            self.thread.join(timeout=2)

    def _run(self):
        interval = 1.0 / self.packets_per_second if self.packets_per_second > 0 else 1.0
        while self.is_running:
            packet = generate_synthetic_packet()
            self.callback(packet)
            time.sleep(interval)
