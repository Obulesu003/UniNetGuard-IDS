export interface Alert {
  id: string;
  timestamp: string;
  severity: "critical" | "high" | "medium" | "low";
  category: string;
  title: string;
  description: string;
  source_ip: string;
  dest_ip: string;
  source_port: number;
  dest_port: number;
  protocol: string;
  signature_id: string;
  detection_method: string;
  resolved: boolean;
  resolved_at?: string;
  resolved_by?: string;
}

export interface LiveStats {
  packets_per_second: number;
  bytes_per_second: number;
  total_packets: number;
  total_bytes: number;
  active_alerts: number;
  protocols: {
    tcp: number;
    udp: number;
    icmp: number;
    other: number;
  };
}

export interface ThroughputPoint {
  timestamp: string;
  packets_per_second: number;
  bytes_per_second: number;
  total_packets: number;
  active_alerts: number;
}

export interface AlertSummary {
  by_severity: Record<string, number>;
  by_category: Record<string, number>;
  by_method: Record<string, number>;
}

export interface CapturedPacket {
  id: string;
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  length: number;
  ttl: number;
  ip_length: number;
  checksum: number;
  tcp_flags: string;
  tcp_seq: number;
  tcp_ack: number;
  window_size: number;
  dns_query: string;
  http_method: string;
  payload_preview: string;
  raw_hex: string;
  is_alert: boolean;
  alert_id: string;
}

export interface PacketStats {
  total_packets: number;
  by_protocol: Record<string, number>;
  top_sources: Array<{ ip: string; count: number }>;
  top_destinations: Array<{ ip: string; count: number }>;
  top_ports: Array<{ port: number; count: number }>;
}
