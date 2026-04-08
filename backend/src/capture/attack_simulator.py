"""Attack simulation using real Scapy packets sent on the live interface.

This generates actual network traffic that triggers real detection —
unlike synthetic traffic which is internal-only and never hits the wire.
"""
import asyncio
import random
import threading
import time
from datetime import datetime
from src.capture.packet_capture import PacketInfo


# Real attack packet generators using Scapy
def _build_attack_packets(interface: str, target_ip: str):
    """Generate real Scapy attack packets on the live interface."""
    try:
        from scapy.all import IP, TCP, ICMP, send, conf
        conf.iface = interface
    except ImportError:
        return

    # ── TCP SYN-FIN Scan ────────────────────────────────────
    # Abnormal: SYN + FIN together — never valid in normal traffic
    for dst_port in random.sample(range(1, 1024), min(15, 1023)):
        try:
            send(IP(src=_random_ip(), dst=target_ip) / TCP(sport=random.randint(1024, 65535), dport=dst_port, flags="SF"), verbose=0)
        except Exception:
            pass

    # ── TCP NULL Scan ───────────────────────────────────────
    # No TCP flags at all — highly suspicious
    for dst_port in random.sample(range(1, 1024), min(10, 1023)):
        try:
            send(IP(src=_random_ip(), dst=target_ip) / TCP(sport=random.randint(1024, 65535), dport=dst_port, flags=0), verbose=0)
        except Exception:
            pass

    # ── TCP Xmas Scan ───────────────────────────────────────
    # FIN + PSH + URG flags — "illuminated like a Christmas tree"
    for dst_port in random.sample(range(1, 1024), min(10, 1023)):
        try:
            send(IP(src=_random_ip(), dst=target_ip) / TCP(sport=random.randint(1024, 65535), dport=dst_port, flags="FPU"), verbose=0)
        except Exception:
            pass

    # ── ICMP Ping Flood ──────────────────────────────────────
    for _ in range(20):
        try:
            send(IP(src=_random_ip(), dst=target_ip) / ICMP(type=8, code=0), verbose=0)
        except Exception:
            pass

    # ── TCP SYN Flood (high volume) ──────────────────────────
    for dst_port in [80, 443, 22, 445, 3389]:
        for _ in range(5):
            try:
                send(IP(src=_random_ip(), dst=target_ip) / TCP(sport=random.randint(1024, 65535), dport=dst_port, flags="S"), verbose=0)
            except Exception:
                pass


def _random_ip() -> str:
    """Generate a fake source IP to simulate external attackers."""
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def _build_normal_packets(interface: str, target_ip: str):
    """Generate normal-looking background traffic."""
    try:
        from scapy.all import IP, TCP, UDP, ICMP, send, conf
        conf.iface = interface
    except ImportError:
        return

    ports = [80, 443, 53, 22, 8080]
    for _ in range(30):
        proto = random.choice(["TCP", "TCP", "TCP", "UDP", "ICMP"])
        try:
            if proto == "TCP":
                send(IP(src=_random_ip(), dst=target_ip) / TCP(
                    sport=random.randint(1024, 65535),
                    dport=random.choice(ports),
                    flags=random.choice(["S", "A", "PA"])
                ), verbose=0)
            elif proto == "UDP":
                send(IP(src=_random_ip(), dst=target_ip) / UDP(
                    sport=random.randint(1024, 65535),
                    dport=random.choice([53, 123, 67])
                ), verbose=0)
            else:
                send(IP(src=_random_ip(), dst=target_ip) / ICMP(type=8, code=0), verbose=0)
        except Exception:
            pass


class AttackSimulator:
    """Sends real Scapy packets on the live interface to trigger detection.

    Unlike SyntheticTrafficGenerator which feeds packets internally,
    AttackSimulator sends actual packets on the wire so the full
    capture → analyze → alert pipeline is exercised.
    """

    def __init__(self, callback, interface: str = None):
        self.callback = callback  # called with PacketInfo for each packet
        self.interface = interface
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
        """Alternate between attack bursts and normal traffic."""
        import socket

        # Determine a reasonable target IP (gateway or localhost)
        target_ip = "127.0.0.1"
        actual_iface = self.interface

        # Try to find a gateway or use localhost
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            # Target the gateway (first 3 octets .1)
            if local_ip != "127.0.0.1":
                parts = local_ip.split(".")
                target_ip = f"{parts[0]}.{parts[1]}.{parts[2]}.1"
        except Exception:
            pass

        interval = 0.05  # Attack burst every 50ms
        burst_count = 0

        while self.is_running:
            if burst_count % 8 == 0:
                # Every 8th burst: send attack packets
                _build_attack_packets(actual_iface, target_ip)
            else:
                # Normal traffic
                _build_normal_packets(actual_iface, target_ip)

            burst_count += 1
            time.sleep(interval)
