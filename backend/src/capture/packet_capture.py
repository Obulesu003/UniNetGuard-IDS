"""Packet capture using tshark directly"""

import os, time, random, subprocess, threading
from pathlib import Path
from typing import Optional, List, Callable, Dict, Any
from dataclasses import dataclass, field
from queue import Queue, Empty
import logging

from ..utils.logger import get_logger
from ..utils.config import get_config

logger = get_logger(__name__)
TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"


@dataclass
class CapturedPacket:
    timestamp: float; src_ip: str; dst_ip: str; src_port: int; dst_port: int
    protocol: str; length: int; tcp_flags: str = ""; payload_size: int = 0
    info: str = ""; ttl: int = 64; payload: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {'timestamp': self.timestamp, 'src_ip': self.src_ip, 'dst_ip': self.dst_ip,
                'src_port': self.src_port, 'dst_port': self.dst_port, 'protocol': self.protocol,
                'length': self.length, 'tcp_flags': self.tcp_flags, 'payload_size': self.payload_size,
                'info': self.info, 'payload': self.payload}


@dataclass
class CaptureStats:
    packets_captured: int = 0; bytes_captured: int = 0
    start_time: float = field(default_factory=time.time); errors: int = 0; last_packet_time: float = 0

    @property
    def duration(self) -> float: return time.time() - self.start_time
    @property
    def packets_per_second(self) -> float: return self.packets_captured / self.duration if self.duration > 0 else 0


class CaptureSession:
    def __init__(self, interface: str, bpf_filter: str = "", output_file: Optional[str] = None, simulate: bool = False):
        self.interface = interface; self.bpf_filter = bpf_filter; self.output_file = output_file
        self.simulate = simulate; self.capture_process = None; self.stats = CaptureStats()
        self.packet_queue: Queue = Queue(); self.running = False
        self._reader_thread: Optional[threading.Thread] = None; self._sim_thread: Optional[threading.Thread] = None
        self._base_time = time.time(); self._callback: Optional[Callable] = None

    def start(self, callback: Optional[Callable[['CapturedPacket'], None]] = None):
        self._base_time = time.time(); self._callback = callback
        if self.simulate:
            logger.info("Starting SIMULATED capture (demo mode)")
            self.running = True
            self._sim_thread = threading.Thread(target=self._simulate_capture, args=(callback,), daemon=True)
            self._sim_thread.start(); return
        if not os.path.exists(TSHARK_PATH):
            logger.warning(f"tshark not found, using simulated mode")
            self.simulate = True; self.running = True
            self._sim_thread = threading.Thread(target=self._simulate_capture, args=(callback,), daemon=True)
            self._sim_thread.start(); return
        try:
            cmd = [TSHARK_PATH, '-i', self.interface, '-T', 'fields',
                   '-e', 'frame.time_relative', '-e', 'ip.proto', '-e', 'ip.src', '-e', 'ip.dst',
                   '-e', 'tcp.srcport', '-e', 'tcp.dstport', '-e', 'udp.srcport', '-e', 'udp.dstport',
                   '-e', 'frame.len', '-E', 'separator=|']
            if self.bpf_filter: cmd.extend(['-f', self.bpf_filter])
            self.capture_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
            self.running = True
            self._reader_thread = threading.Thread(target=self._read_output, args=(callback,), daemon=True)
            self._reader_thread.start(); logger.info("Capture started successfully")
        except Exception as e:
            logger.error(f"Failed to start capture: {e}"); raise

    def _simulate_capture(self, callback):
        ports = [80, 443, 22, 53, 8080, 3306, 5432, 25]
        while self.running:
            try:
                time.sleep(random.uniform(0.01, 0.1))
                packet = CapturedPacket(
                    timestamp=time.time() - self._base_time,
                    src_ip=f"192.168.1.{random.randint(10, 200)}",
                    dst_ip=f"192.168.1.{random.randint(1, 9)}",
                    src_port=random.randint(40000, 60000),
                    dst_port=random.choice(ports),
                    protocol=random.choice(['TCP', 'UDP', 'TCP', 'TCP', 'UDP', 'TCP']),
                    length=random.randint(40, 1500))
                self.stats.packets_captured += 1; self.stats.bytes_captured += packet.length
                self.stats.last_packet_time = packet.timestamp
                if callback: callback(packet)
                self.packet_queue.put(packet)
            except Exception as e: logger.debug(f"Sim error: {e}")

    def _read_output(self, callback):
        while self.running and self.capture_process:
            try:
                line = self.capture_process.stdout.readline()
                if not line: break
                line = line.strip()
                if not line: continue
                packet = self._parse_tshark_fields(line)
                if packet:
                    self.stats.packets_captured += 1; self.stats.bytes_captured += packet.length
                    self.stats.last_packet_time = packet.timestamp
                    if callback: callback(packet)
                    self.packet_queue.put(packet)
            except Exception: pass

    def _parse_tshark_fields(self, line: str) -> Optional[CapturedPacket]:
        parts = line.split('|')
        if len(parts) < 9: return None
        try:
            ts = float(parts[0]); proto_num = parts[1]; src_ip = parts[2]; dst_ip = parts[3]
            if proto_num == '6': protocol = 'TCP'; src_port = int(parts[4]) if parts[4] else 0; dst_port = int(parts[5]) if parts[5] else 0
            elif proto_num == '17': protocol = 'UDP'; src_port = int(parts[6]) if parts[6] else 0; dst_port = int(parts[7]) if parts[7] else 0
            elif proto_num == '1': protocol = 'ICMP'; src_port = dst_port = 0
            else: protocol = 'Unknown'; src_port = dst_port = 0
            length = int(parts[8]) if parts[8] else 0
            return CapturedPacket(timestamp=ts, src_ip=src_ip or 'unknown', dst_ip=dst_ip or 'unknown',
                                  src_port=src_port, dst_port=dst_port, protocol=protocol, length=length,
                                  info=f"{protocol} {src_port} -> {dst_port}")
        except Exception: return None

    def stop(self):
        logger.info("Stopping capture..."); self.running = False
        if self.capture_process:
            self.capture_process.terminate()
            try: self.capture_process.wait(timeout=2)
            except subprocess.TimeoutExpired: self.capture_process.kill()
        if self._reader_thread and self._reader_thread.is_alive(): self._reader_thread.join(timeout=2)
        logger.info(f"Capture stopped. Total packets: {self.stats.packets_captured}")

    def get_packet(self, timeout: float = 1.0) -> Optional[CapturedPacket]:
        try: return self.packet_queue.get(timeout=timeout)
        except Empty: return None
    def get_stats(self) -> CaptureStats: return self.stats


class PacketCapture:
    def __init__(self, config=None):
        self.config = config or get_config()
        self._session: Optional[CaptureSession] = None
        self._capture_lock = threading.Lock()

    def get_available_interfaces(self) -> List[Dict[str, Any]]:
        interfaces = []
        try:
            result = subprocess.run([TSHARK_PATH, '-D'], capture_output=True, text=True, timeout=5)
            for line in result.stdout.strip().split('\n'):
                if line.strip() and '.' in line:
                    parts = line.split('.', 1)
                    if len(parts) >= 2:
                        interfaces.append({'name': parts[0].strip(), 'description': parts[1].strip()})
        except Exception as e:
            logger.error(f"Error getting interfaces: {e}")
            interfaces.append({'name': '5', 'description': 'Wi-Fi (default)'})
        return interfaces if interfaces else [{'name': '5', 'description': 'Wi-Fi'}]

    def start_capture(self, interface: Optional[str] = None, bpf_filter: str = "", output_file: Optional[str] = None,
                      callback: Optional[Callable[['CapturedPacket'], None]] = None, simulate: bool = False) -> CaptureSession:
        with self._capture_lock:
            if self._session and self._session.running:
                logger.warning("Capture already running, stopping first"); self.stop_capture()
            interface = interface or self.config.capture.interface
            if interface == "auto":
                interfaces = self.get_available_interfaces()
                if interfaces: interface = interfaces[0]['name']
                else: raise RuntimeError("No network interfaces found")
            filter_str = bpf_filter or self.config.capture.filter
            should_simulate = simulate or not os.path.exists(TSHARK_PATH)
            self._session = CaptureSession(interface, filter_str, output_file, simulate=should_simulate)
            self._session.start(callback); return self._session

    def stop_capture(self):
        with self._capture_lock:
            if self._session: self._session.stop(); self._session = None

    def is_capturing(self) -> bool: return self._session is not None and self._session.running
    def get_session(self) -> Optional[CaptureSession]: return self._session


def get_interfaces() -> List[Dict[str, Any]]: return PacketCapture().get_available_interfaces()
def start_capture(interface: Optional[str] = None, bpf_filter: str = "", output_file: Optional[str] = None,
                   callback: Optional[Callable[['CapturedPacket'], None]] = None) -> CaptureSession:
    return PacketCapture().start_capture(interface, bpf_filter, output_file, callback)
def stop_capture(): PacketCapture().stop_capture()
