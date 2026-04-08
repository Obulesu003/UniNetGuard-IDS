"""Feature extraction for ML model - matching CICIDS2017 format"""
from typing import Dict, List, Any
from dataclasses import dataclass


FEATURE_NAMES = [
    'flow_duration', 'total_fwd_packets', 'total_bwd_packets',
    'total_length_fwd', 'total_length_bwd',
    'fwd_packet_length_max', 'fwd_packet_length_min', 'fwd_packet_length_mean', 'fwd_packet_length_std',
    'bwd_packet_length_max', 'bwd_packet_length_min', 'bwd_packet_length_mean', 'bwd_packet_length_std',
    'flow_bytes_per_sec', 'flow_packets_per_sec', 'flow_iat_mean', 'flow_iat_std',
    'fwd_iat_total', 'fwd_iat_mean', 'fwd_iat_std', 'fwd_iat_max', 'fwd_iat_min',
    'bwd_iat_total', 'bwd_iat_mean', 'bwd_iat_std', 'bwd_iat_max', 'bwd_iat_min',
    'active_mean', 'active_std', 'active_max', 'active_min',
    'idle_mean', 'idle_std', 'idle_max', 'idle_min',
    'destination_port', 'packet_length_mean', 'packet_length_std',
    'down_up_ratio', 'average_packet_size', 'avg_fwd_segment_size', 'avg_bwd_segment_size',
    'fwd_header_length', 'bwd_header_length', 'fwd_packets_per_sec', 'bwd_packets_per_sec',
    'min_packet_length', 'max_packet_length',
    'syn_flag_count', 'rst_flag_count', 'psh_flag_count', 'ack_flag_count', 'urg_flag_count',
    'init_win_bytes_forward', 'init_win_bytes_backward',
    'act_data_pkt_fwd', 'min_seg_size_forward',
    'subflow_fwd_packets', 'subflow_fwd_bytes', 'subflow_bwd_packets', 'subflow_bwd_bytes',
    'packet_count', 'byte_count', 'duration', 'packets_per_second', 'bytes_per_second',
    'tcp_ratio', 'udp_ratio', 'icmp_ratio', 'unique_src_ips', 'unique_dst_ips',
    'unique_src_ports', 'unique_dst_ports', 'port_scan_score',
    'sql_injection_count', 'xss_count', 'web_payload_count', 'brute_force_count',
    'dos_packets', 'bot_beacon_score'
]


@dataclass
class ExtractedFeatures:
    features: Dict[str, float]
    raw_data: Dict[str, Any]

    def to_list(self) -> List[float]:
        return [self.features.get(name, 0.0) for name in FEATURE_NAMES]

    def to_dict(self) -> Dict[str, float]:
        return self.features.copy()


class FeatureExtractor:
    """Extract features from traffic data matching CICIDS2017 format"""

    def __init__(self):
        self.feature_names = FEATURE_NAMES

    def extract(self, traffic_data: Dict[str, Any]) -> ExtractedFeatures:
        """Extract features from traffic statistics"""
        features = {}
        duration = max(traffic_data.get('duration', 1), 0.001)
        total_packets = traffic_data.get('total_packets', 0) or traffic_data.get('packet_count', 0)
        total_bytes = traffic_data.get('total_bytes', 0) or traffic_data.get('byte_count', 0)

        features['flow_duration'] = duration
        features['duration'] = duration
        features['total_fwd_packets'] = int(total_packets * 0.6)
        features['total_bwd_packets'] = int(total_packets * 0.4)
        features['packet_count'] = total_packets
        features['total_length_fwd'] = int(total_bytes * 0.6)
        features['total_length_bwd'] = int(total_bytes * 0.4)
        features['byte_count'] = total_bytes

        avg_size = traffic_data.get('avg_packet_size', 60)
        features['fwd_packet_length_max'] = avg_size * 1.2
        features['fwd_packet_length_min'] = avg_size * 0.7
        features['fwd_packet_length_mean'] = avg_size * 0.9
        features['fwd_packet_length_std'] = avg_size * 0.3
        features['bwd_packet_length_max'] = avg_size * 1.1
        features['bwd_packet_length_min'] = avg_size * 0.6
        features['bwd_packet_length_mean'] = avg_size * 0.85
        features['bwd_packet_length_std'] = avg_size * 0.25
        features['packet_length_mean'] = avg_size
        features['packet_length_std'] = avg_size * 0.3
        features['average_packet_size'] = avg_size
        features['min_packet_length'] = 40
        features['max_packet_length'] = 1500

        pps = traffic_data.get('packets_per_second', 0)
        bps = traffic_data.get('bytes_per_second', 0)
        features['flow_bytes_per_sec'] = bps
        features['flow_packets_per_sec'] = pps
        features['packets_per_second'] = pps
        features['bytes_per_second'] = bps
        features['fwd_packets_per_sec'] = pps * 0.6
        features['bwd_packets_per_sec'] = pps * 0.4

        features['flow_iat_mean'] = 1.0 / max(pps, 0.001)
        features['flow_iat_std'] = features['flow_iat_mean'] * 0.5
        features['fwd_iat_total'] = duration * 0.6
        features['fwd_iat_mean'] = features['flow_iat_mean'] * 1.2
        features['fwd_iat_std'] = features['fwd_iat_mean'] * 0.4
        features['fwd_iat_max'] = features['fwd_iat_mean'] * 5
        features['fwd_iat_min'] = features['fwd_iat_mean'] * 0.1
        features['bwd_iat_total'] = duration * 0.4
        features['bwd_iat_mean'] = features['flow_iat_mean'] * 1.5
        features['bwd_iat_std'] = features['bwd_iat_mean'] * 0.4
        features['bwd_iat_max'] = features['bwd_iat_mean'] * 5
        features['bwd_iat_min'] = features['bwd_iat_mean'] * 0.1

        features['active_mean'] = duration / max(total_packets, 1) * 10
        features['active_std'] = features['active_mean'] * 0.3
        features['active_max'] = features['active_mean'] * 3
        features['active_min'] = features['active_mean'] * 0.2
        features['idle_mean'] = features['active_mean'] * 0.5
        features['idle_std'] = features['idle_mean'] * 0.3
        features['idle_max'] = features['idle_mean'] * 2
        features['idle_min'] = features['idle_mean'] * 0.2

        prot_dist = traffic_data.get('protocol_distribution', {})
        total_prot = sum(prot_dist.values()) or 1
        tcp_count = prot_dist.get('TCP', 0)
        udp_count = prot_dist.get('UDP', 0)
        icmp_count = prot_dist.get('ICMP', 0)

        features['tcp_ratio'] = tcp_count / total_prot
        features['udp_ratio'] = udp_count / total_prot
        features['icmp_ratio'] = icmp_count / total_prot
        features['unique_src_ips'] = traffic_data.get('unique_src_ips', 1)
        features['unique_dst_ips'] = traffic_data.get('unique_dst_ips', 1)
        features['unique_src_ports'] = traffic_data.get('unique_src_ports', 1)
        features['unique_dst_ports'] = traffic_data.get('unique_dst_ports', 1)

        top_ports = traffic_data.get('top_dst_ports', {})
        features['destination_port'] = list(top_ports.keys())[0] if top_ports else 80

        features['syn_flag_count'] = int(tcp_count * 0.1)
        features['rst_flag_count'] = 0
        features['psh_flag_count'] = int(tcp_count * 0.2)
        features['ack_flag_count'] = int(tcp_count * 0.7)
        features['urg_flag_count'] = 0
        features['init_win_bytes_forward'] = 65535
        features['init_win_bytes_backward'] = 65535
        features['act_data_pkt_fwd'] = int(total_packets * 0.5)
        features['min_seg_size_forward'] = 32
        features['subflow_fwd_packets'] = int(total_packets * 0.6)
        features['subflow_fwd_bytes'] = int(total_bytes * 0.6)
        features['subflow_bwd_packets'] = int(total_packets * 0.4)
        features['subflow_bwd_bytes'] = int(total_bytes * 0.4)
        features['avg_fwd_segment_size'] = avg_size * 0.9
        features['avg_bwd_segment_size'] = avg_size * 0.85
        features['fwd_header_length'] = 54
        features['bwd_header_length'] = 54
        features['down_up_ratio'] = features['total_length_fwd'] / max(features['total_length_bwd'], 1)

        dst_ports = features['unique_dst_ports']
        src_ips = features['unique_src_ips']
        if dst_ports >= 15:
            features['port_scan_score'] = min((dst_ports / 50) * (1.0 / max(src_ips, 1) ** 0.3), 1.0)
        else:
            features['port_scan_score'] = 0.0

        features['sql_injection_count'] = traffic_data.get('sql_injection_count', 0)
        features['xss_count'] = traffic_data.get('xss_count', 0)
        features['web_payload_count'] = traffic_data.get('web_payload_count', 0)
        features['brute_force_count'] = traffic_data.get('brute_force_count', 0)
        features['dos_packets'] = traffic_data.get('dos_packets', 0)
        features['bot_beacon_score'] = traffic_data.get('bot_beacon_score', 0)

        features['dst_ports_per_src'] = dst_ports / max(src_ips, 1)
        features['src_ports_per_src'] = features['unique_src_ports'] / max(src_ips, 1)
        syn_count = features['syn_flag_count']
        ack_count = features['ack_flag_count']
        features['syn_ack_ratio'] = syn_count / max(ack_count, 1)
        features['fwd_packets_ratio'] = features['total_fwd_packets'] / max(total_packets, 1)

        return ExtractedFeatures(features=features, raw_data=traffic_data)

    def get_feature_names(self) -> List[str]:
        return self.feature_names.copy()


def extract_features(traffic_data: Dict[str, Any]) -> ExtractedFeatures:
    """Convenience function to extract features"""
    extractor = FeatureExtractor()
    return extractor.extract(traffic_data)
