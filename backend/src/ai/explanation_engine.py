"""AI-powered explanation engine for traffic analysis"""

import os
import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime
import logging

from ..utils.logger import get_logger
from ..utils.config import get_config

logger = get_logger(__name__)


@dataclass
class TrafficExplanation:
    summary: str
    threat_analysis: Optional[str]
    ai_explanation: Optional[str]
    recommendations: List[str]
    raw_response: Optional[str]
    provider: str
    timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            'summary': self.summary,
            'threat_analysis': self.threat_analysis,
            'ai_explanation': self.ai_explanation,
            'recommendations': self.recommendations,
            'raw_response': self.raw_response,
            'provider': self.provider,
            'timestamp': self.timestamp
        }

    def to_markdown(self) -> str:
        lines = []
        lines.append("## Traffic Analysis\n")
        lines.append(f"**Generated:** {self.timestamp}\n")
        lines.append(f"**Provider:** {self.provider}\n")
        lines.append("\n### Summary\n")
        lines.append(self.summary)
        if self.threat_analysis:
            lines.append("\n### Threat Analysis\n")
            lines.append(self.threat_analysis)
        if self.ai_explanation:
            lines.append("\n### AI Explanation\n")
            lines.append(self.ai_explanation)
        if self.recommendations:
            lines.append("\n### Recommended Actions\n")
            for i, rec in enumerate(self.recommendations, 1):
                lines.append(f"{i}. {rec}")
        return "\n".join(lines)


ATTACK_EXPLANATIONS = {
    'BENIGN': {
        'summary': 'Traffic appears normal with no suspicious patterns detected.',
        'threat': None,
        'explanation': 'The analyzed network traffic shows typical behavior consistent with normal network operations.',
        'recommendations': [
            'Continue monitoring for any changes in traffic patterns',
            'Review this analysis periodically',
            'Ensure all security measures are up to date'
        ]
    },
    'Bot': {
        'summary': 'Potential botnet activity detected - compromised host may be communicating with command server.',
        'threat': 'A host appears to be exhibiting bot-like behavior, potentially part of a botnet.',
        'explanation': 'The traffic pattern shows characteristics typical of bot infections: regular beacons to external servers, unusual port usage, and potential data exfiltration attempts.',
        'recommendations': [
            'Isolate the affected host immediately',
            'Run a full malware scan on the host',
            'Check for unauthorized processes and scheduled tasks',
            'Review authentication logs for compromise indicators',
            'Block identified C2 server IPs at the firewall'
        ]
    },
    'Brute Force': {
        'summary': 'Brute force attack detected - multiple login attempts targeting authentication services.',
        'threat': 'An attacker is attempting to gain unauthorized access through repeated login attempts.',
        'explanation': 'The traffic shows a high volume of connection attempts to authentication services (SSH, FTP, etc.) from one or more sources, characteristic of credential stuffing attacks.',
        'recommendations': [
            'Implement rate limiting on authentication endpoints',
            'Enable account lockout policies',
            'Consider implementing MFA/2FA',
            'Block source IPs at firewall',
            'Review and strengthen password policies',
            'Enable comprehensive logging for authentication events'
        ]
    },
    'DoS': {
        'summary': 'Denial of Service attack detected - service availability may be impacted.',
        'threat': 'A DoS attack is overwhelming network resources or specific services.',
        'explanation': 'Unusual traffic volume detected with patterns consistent with Denial of Service attacks. This may be a flood attack (SYN, UDP) or application-layer DoS.',
        'recommendations': [
            'Enable DDoS protection if available',
            'Rate limit at the network edge',
            'Block attack source IPs',
            'Scale infrastructure if under attack',
            'Contact ISP for upstream filtering',
            'Review and implement traffic scrubbing'
        ]
    },
    'Port Scan': {
        'summary': 'Port scan detected - reconnaissance activity preceding potential attack.',
        'threat': 'An attacker is mapping your network to identify vulnerabilities.',
        'explanation': 'Sequential connection attempts to multiple ports or hosts detected. This is classic reconnaissance behavior, typically the first phase of a targeted attack.',
        'recommendations': [
            'Block source IP at firewall',
            'Review firewall rules and close unnecessary ports',
            'Enable IDS/IPS alerts for port scan signatures',
            'Monitor for follow-up exploitation attempts',
            'Consider implementing port scan detection tools'
        ]
    },
    'SQL Injection': {
        'summary': 'SQL injection attack detected - malicious code in web requests.',
        'threat': 'An attacker is attempting to manipulate database queries through your web application.',
        'explanation': 'HTTP requests contain suspicious SQL syntax and database commands that do not match legitimate user behavior.',
        'recommendations': [
            'Validate and sanitize all user inputs immediately',
            'Review web application code for SQL injection vulnerabilities',
            'Use parameterized queries or ORM',
            'Implement WAF rules for SQL injection signatures',
            'Audit database permissions',
            'Check for successful injection attempts'
        ]
    },
    'XSS': {
        'summary': 'Cross-Site Scripting (XSS) attempt detected - malicious scripts in web traffic.',
        'threat': 'An attacker is attempting to inject client-side scripts into your web pages.',
        'explanation': 'Web requests contain suspicious JavaScript or HTML patterns that may indicate XSS payload delivery.',
        'recommendations': [
            'Sanitize all user inputs and outputs',
            'Implement Content Security Policy (CSP)',
            'Use HTTPOnly and Secure flags on cookies',
            'Validate and encode user input',
            'Review web application for reflected/stored XSS',
            'Consider WAF deployment for XSS protection'
        ]
    },
    'Infiltration': {
        'summary': 'Infiltration detected - potential unauthorized access or data exfiltration.',
        'threat': 'A host may be compromised with data being extracted from the network.',
        'explanation': 'Traffic patterns suggest unauthorized access or data exfiltration from internal hosts.',
        'recommendations': [
            'Immediately isolate affected hosts',
            'Preserve forensic evidence',
            'Conduct thorough malware analysis',
            'Review network logs for scope of breach',
            'Reset credentials for affected systems',
            'Report to security team and follow incident response procedures'
        ]
    },
    'Vulnerability': {
        'summary': 'Vulnerability exploitation attempt detected - specific CVE being targeted.',
        'threat': 'An attacker is attempting to exploit a known vulnerability in your systems.',
        'explanation': 'Traffic patterns match signatures for known vulnerability exploitation attempts.',
        'recommendations': [
            'Patch vulnerable systems immediately',
            'Check for indicators of successful exploitation',
            'Review vulnerability scan results',
            'Implement intrusion detection signatures',
            'Consider removing affected systems from network until patched'
        ]
    },
    'Web Attack': {
        'summary': 'Web application attack detected - various web-based threats.',
        'threat': 'Your web application is under attack through various web exploitation techniques.',
        'explanation': 'HTTP traffic contains patterns associated with common web application attacks including injection, authentication bypass, and parameter manipulation.',
        'recommendations': [
            'Review web application logs for attack attempts',
            'Implement WAF rules',
            'Validate all user inputs server-side',
            'Use secure coding practices',
            'Regular security testing of web applications',
            'Consider implementing bot protection'
        ]
    }
}


class ExplanationEngine:
    def __init__(self, config=None):
        self.config = config or get_config()
        self.ai_config = self.config.ai
        self.explanation_level = self.ai_config.explanation_level

    def generate(self, traffic_data: Dict[str, Any], classification: Dict[str, Any]) -> TrafficExplanation:
        label = classification.get('label', 'BENIGN')
        confidence = classification.get('confidence', 0)
        category = classification.get('category', 'Normal')
        is_threat = classification.get('is_threat', False)
        all_detected = classification.get('all_detected_attacks', [])

        template_info = ATTACK_EXPLANATIONS.get(label, ATTACK_EXPLANATIONS['BENIGN'])

        summary = self._generate_summary(traffic_data, classification, all_detected)

        if is_threat:
            threat_analysis = self._generate_threat_analysis(label, confidence, traffic_data, all_detected)
            ai_explanation = self._generate_ai_explanation(
                traffic_data, classification, template_info['explanation']
            )
            recommendations = template_info['recommendations']
        else:
            threat_analysis = None
            ai_explanation = None
            recommendations = template_info['recommendations']

        return TrafficExplanation(
            summary=summary,
            threat_analysis=threat_analysis,
            ai_explanation=ai_explanation,
            recommendations=recommendations,
            raw_response=None,
            provider='template',
            timestamp=datetime.now().isoformat()
        )

    def _generate_summary(self, traffic_data: Dict[str, Any], classification: Dict[str, Any],
                          all_detected: List[str] = None) -> str:
        packets = traffic_data.get('packet_count', 0)
        bytes_total = traffic_data.get('byte_count', 0)
        duration = traffic_data.get('duration', 0)
        pps = traffic_data.get('packets_per_second', 0)
        bps = traffic_data.get('bytes_per_second', 0)

        protocols = []
        for proto, ratio_key in [('TCP', 'tcp_ratio'), ('UDP', 'udp_ratio'), ('ICMP', 'icmp_ratio')]:
            ratio = traffic_data.get(ratio_key, 0)
            if ratio > 0.05:
                protocols.append(f"{proto} {ratio*100:.0f}%")

        protocol_str = ', '.join(protocols) if protocols else 'Unknown'
        src_ips = traffic_data.get('unique_src_ips', 0)
        dst_ips = traffic_data.get('unique_dst_ips', 0)
        unique_ports = traffic_data.get('unique_dst_ports', 0)

        category = classification.get('category', 'Normal')
        attacks = all_detected or []

        if attacks:
            severity = len(attacks)
            severity_icon = "[!]" if severity >= 3 else "[*]" if severity >= 2 else "[>]"
            summary = f"{severity_icon} **{category}** | {packets} packets | {duration:.1f}s | {protocol_str}\n"
            summary += f"   Sources: {src_ips} | Dest: {dst_ips} ({unique_ports} ports) | Rate: {pps:.1f} pps\n"
            summary += f"   **Threats ({len(attacks)}):** {', '.join(attacks)}"
        else:
            traffic_level = "High"
            if pps <= 100:
                traffic_level = "Medium"
            if pps <= 20:
                traffic_level = "Low"

            summary = f"[OK] **{category}** | {packets} packets | {duration:.1f}s | {protocol_str}\n"
            summary += f"   Traffic: {traffic_level} ({pps:.1f} pps, {bps/1024:.1f} KB/s)\n"
            summary += f"   Sources: {src_ips} | Destinations: {dst_ips} | Ports: {unique_ports}"

        return summary

    def _generate_threat_analysis(
        self,
        label: str,
        confidence: float,
        traffic_data: Dict[str, Any],
        all_detected: List[str] = None
    ) -> str:
        confidence_pct = confidence * 100
        attacks = all_detected or []

        total_packets = traffic_data.get('total_packets', 0)
        total_bytes = traffic_data.get('total_bytes', 0)
        pps = traffic_data.get('packets_per_second', 0)
        bps = traffic_data.get('bytes_per_second', 0)
        duration = traffic_data.get('duration', 0)
        unique_src = traffic_data.get('unique_src_ips', 0)
        unique_dst = traffic_data.get('unique_dst_ips', 0)
        unique_ports = traffic_data.get('unique_dst_ports', 0)
        tcp_ratio = traffic_data.get('tcp_ratio', 0) * 100
        udp_ratio = traffic_data.get('udp_ratio', 0) * 100

        analysis = f"**Attack Type:** {label}\n"
        analysis += f"**Confidence:** {confidence_pct:.1f}%\n"
        analysis += f"**Duration:** {duration:.1f}s | **Packets:** {total_packets:,} | **Volume:** {total_bytes/1024:.1f} KB\n\n"

        if len(attacks) > 1:
            analysis += f"**Multiple attack vectors detected:** {', '.join(attacks)}\n\n"

        if label == 'Port Scan':
            analysis += f"**Reconnaissance Activity Detected**\n"
            analysis += f"- Scanned {unique_ports} unique ports across {unique_dst} target(s)\n"
            analysis += f"- Traffic pattern: {pps:.1f} packets/sec with {tcp_ratio:.0f}% TCP\n"
            analysis += f"- Source diversity: {unique_src} unique source(s)\n\n"
            analysis += f"**Threat Assessment:** "
            if unique_ports > 50:
                analysis += "Aggressive scanning behavior indicating sophisticated attacker\n"
            elif unique_ports > 20:
                analysis += "Moderate port enumeration - likely looking for specific services\n"
            else:
                analysis += "Limited reconnaissance - targeted service discovery\n"

        elif 'Brute Force' in label:
            attempt_count = traffic_data.get('brute_force_count', 0)
            target_ports = list(traffic_data.get('top_dst_ports', {}).keys())[:3]
            port_names = {22: 'SSH', 21: 'FTP', 23: 'Telnet', 25: 'SMTP', 3306: 'MySQL', 5432: 'PostgreSQL', 8080: 'HTTP-Alt'}
            targets = [f"{port} ({port_names.get(port, 'Unknown')})" for port in target_ports[:3]]

            analysis += f"**Credential Attack Detected**\n"
            analysis += f"- {attempt_count}+ authentication attempts observed\n"
            analysis += f"- Targeting: {', '.join(targets)}\n"
            analysis += f"- Rate: {pps:.1f} attempts/sec\n\n"
            analysis += f"**Threat Assessment:** "
            if attempt_count > 100:
                analysis += "Sustained attack campaign - automated tool likely\n"
            elif attempt_count > 50:
                analysis += "Persistent attack - multiple credential attempts\n"
            else:
                analysis += "Initial probing - attacker mapping defenses\n"

        elif 'DoS' in label:
            dos_count = traffic_data.get('dos_packets', 0)
            analysis += f"**Denial of Service Detected**\n"
            analysis += f"- Attack volume: {dos_count}+ malicious packets\n"
            analysis += f"- Throughput: {bps/1024:.1f} KB/sec | Rate: {pps:.1f} pps\n"
            analysis += f"- Protocol mix: TCP {tcp_ratio:.0f}% / UDP {udp_ratio:.0f}%\n\n"
            analysis += f"**Threat Assessment:** "
            if pps > 1000:
                analysis += "Volumetric attack - bandwidth saturation\n"
            elif pps > 100:
                analysis += "Application layer DoS - service degradation likely\n"
            else:
                analysis += "Low-volume DoS - possible slowloris or application exploit\n"

        elif label == 'Bot':
            bot_score = traffic_data.get('bot_beacon_score', 0)
            analysis += f"**Botnet Communication Detected**\n"
            analysis += f"- Beacon score: {bot_score:.1f}/10\n"
            analysis += f"- Targets: {unique_dst} unique destination(s)\n"
            analysis += f"- Pattern: Regular interval communication detected\n\n"
            analysis += f"**Threat Assessment:** "
            if bot_score > 7:
                analysis += "Confirmed bot behavior - immediate isolation recommended\n"
            else:
                analysis += "Potential compromised host - investigate for C2\n"

        elif 'SQL Injection' in label:
            sql_count = traffic_data.get('sql_injection_count', 0)
            analysis += f"**SQL Injection Attack Detected**\n"
            analysis += f"- Malicious payloads: {sql_count}+\n"
            analysis += f"- Through HTTP to {unique_dst} target(s)\n\n"
            analysis += f"**Threat Assessment:** Database compromise risk - audit application logs\n"

        elif 'XSS' in label:
            xss_count = traffic_data.get('xss_count', 0)
            web_payload = traffic_data.get('web_payload_count', 0)
            analysis += f"**Cross-Site Scripting Detected**\n"
            analysis += f"- XSS patterns: {xss_count} | Web payloads: {web_payload}\n"
            analysis += f"- Target(s): {unique_dst}\n\n"
            analysis += f"**Threat Assessment:** Client-side attack - may affect users\n"

        return analysis

    def _generate_ai_explanation(
        self,
        traffic_data: Dict[str, Any],
        classification: Dict[str, Any],
        base_explanation: str
    ) -> str:
        label = classification.get('label', 'Unknown')

        explanation = base_explanation + "\n\n"

        if self.explanation_level == 'brief':
            return explanation

        pps = traffic_data.get('packets_per_second', 0)
        unique_ports = traffic_data.get('unique_dst_ports', 0)

        explanation += "**Technical Details:**\n"
        explanation += f"- Traffic rate: {pps:.2f} packets/second\n"
        explanation += f"- Unique destination ports: {unique_ports}\n"
        explanation += f"- Classification confidence: {classification.get('confidence', 0)*100:.1f}%\n\n"

        explanation += "**Context:**\n"
        if label == 'Port Scan':
            explanation += "Port scanning is typically the first phase of a cyber attack. "
            explanation += "Attackers use this to discover which services are running before attempting exploits.\n"
        elif 'Brute Force' in label:
            explanation += "Brute force attacks exploit weak or default credentials. "
            explanation += "Attackers automate login attempts until they find valid credentials.\n"
        elif 'DoS' in label:
            explanation += "DoS attacks aim to make services unavailable by overwhelming resources. "
            explanation += "This can be achieved through flood attacks, protocol exploits, or application-layer attacks.\n"

        return explanation

    async def generate_with_openai(
        self,
        traffic_data: Dict[str, Any],
        classification: Dict[str, Any]
    ) -> Optional[TrafficExplanation]:
        if not self.ai_config.api_key:
            logger.debug("No OpenAI API key configured, using template explanations")
            return self.generate(traffic_data, classification)

        try:
            from openai import AsyncOpenAI

            client = AsyncOpenAI(api_key=self.ai_config.api_key)
            prompt = self._build_openai_prompt(traffic_data, classification)

            response = await client.chat.completions.create(
                model=self.ai_config.model,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert analyzing network traffic. Provide clear, actionable explanations."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=500
            )

            return self._parse_openai_response(response, traffic_data, classification)

        except Exception as e:
            logger.error(f"OpenAI API error: {e}")
            return self.generate(traffic_data, classification)

    def _build_openai_prompt(self, traffic_data: Dict[str, Any], classification: Dict[str, Any]) -> str:
        label = classification.get('label', 'BENIGN')
        confidence = classification.get('confidence', 0)

        prompt = f"Analyze this network traffic:\n"
        prompt += f"- Classification: {label} (confidence: {confidence*100:.1f}%)\n"
        prompt += f"- Packets: {traffic_data.get('packet_count', 0)}\n"
        prompt += f"- Packets/sec: {traffic_data.get('packets_per_second', 0):.2f}\n"
        prompt += f"- Bytes: {traffic_data.get('byte_count', 0)}\n"
        prompt += f"- TCP ratio: {traffic_data.get('tcp_ratio', 0)*100:.1f}%\n"
        prompt += f"- UDP ratio: {traffic_data.get('udp_ratio', 0)*100:.1f}%\n"
        prompt += f"- Unique source IPs: {traffic_data.get('unique_src_ips', 0)}\n"
        prompt += f"- Unique destination ports: {traffic_data.get('unique_dst_ports', 0)}\n"

        if classification.get('is_threat', False):
            prompt += "\nProvide: 1) Brief explanation of the threat, 2) Key indicators, 3) Recommended actions"
        else:
            prompt += "\nConfirm this is normal traffic and note any observations."

        return prompt

    def _parse_openai_response(
        self,
        response: Any,
        traffic_data: Dict[str, Any],
        classification: Dict[str, Any]
    ) -> TrafficExplanation:
        content = response.choices[0].message.content

        label = classification.get('label', 'BENIGN')
        confidence = classification.get('confidence', 0)
        all_detected = classification.get('all_detected_attacks', [])

        return TrafficExplanation(
            summary=self._generate_summary(traffic_data, classification, all_detected),
            threat_analysis=self._generate_threat_analysis(label, confidence, traffic_data, all_detected),
            ai_explanation=content,
            recommendations=ATTACK_EXPLANATIONS.get(label, {}).get('recommendations', []),
            raw_response=content,
            provider='openai',
            timestamp=datetime.now().isoformat()
        )


def generate_explanation(
    traffic_data: Dict[str, Any],
    classification: Dict[str, Any]
) -> TrafficExplanation:
    engine = ExplanationEngine()
    return engine.generate(traffic_data, classification)
