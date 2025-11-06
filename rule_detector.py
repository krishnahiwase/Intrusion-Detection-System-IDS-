"""
Rule-based Detection System
Implements rule-based intrusion detection using predefined security rules
"""

import logging
import re
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Dict, List, Optional, Any
import ipaddress

class RuleBasedDetector:
    """Rule-based Network Intrusion Detection System"""
    
    def __init__(self, rules_config=None):
        """
        Initialize rule-based detector
        
        Args:
            rules_config: Configuration for detection rules
        """
        self.logger = logging.getLogger(__name__)
        self.rules_config = rules_config or {}
        
        # Rule categories
        self.rules = {
            'port_scan': self._init_port_scan_rules(),
            'ddos': self._init_ddos_rules(),
            'brute_force': self._init_brute_force_rules(),
            'malware': self._init_malware_rules(),
            'policy_violation': self._init_policy_violation_rules(),
            'suspicious_traffic': self._init_suspicious_traffic_rules()
        }
        
        # Tracking data structures
        self.connection_tracker = defaultdict(lambda: {
            'count': 0,
            'timestamps': deque(maxlen=100),
            'ports': set(),
            'flags': defaultdict(int)
        })
        
        self.ip_tracker = defaultdict(lambda: {
            'connections': 0,
            'unique_ports': set(),
            'first_seen': None,
            'last_seen': None,
            'failed_attempts': 0
        })
        
        self.protocol_tracker = defaultdict(int)
        self.alert_thresholds = self.rules_config.get('thresholds', {
            'port_scan_ports': 10,
            'port_scan_time_window': 60,  # seconds
            'ddos_connection_rate': 100,  # connections per minute
            'brute_force_attempts': 5,
            'brute_force_time_window': 300  # seconds
        })
        
        self.logger.info("Rule-based detector initialized")
    
    def _init_port_scan_rules(self):
        """Initialize port scan detection rules"""
        return {
            'suspicious_ports': [135, 139, 445, 1433, 3306, 3389, 5432, 27017],
            'scan_patterns': [
                {'ports': [22, 23, 21, 25, 80, 443], 'threshold': 5},
                {'ports': [135, 139, 445], 'threshold': 3},
                {'ports': [1433, 3306, 5432], 'threshold': 3}
            ],
            'rapid_connection_threshold': 10,
            'time_window': 60
        }
    
    def _init_ddos_rules(self):
        """Initialize DDoS detection rules"""
        return {
            'connection_rate_threshold': 100,  # per minute
            'packet_rate_threshold': 1000,     # per minute
            'bandwidth_threshold': 100 * 1024 * 1024,  # 100MB per minute
            'syn_flood_threshold': 50,
            'udp_flood_threshold': 100,
            'icmp_flood_threshold': 50
        }
    
    def _init_brute_force_rules(self):
        """Initialize brute force detection rules"""
        return {
            'failed_login_ports': [22, 23, 3389, 21, 3306, 5432],
            'failed_attempt_threshold': 5,
            'time_window': 300,  # 5 minutes
            'consecutive_failures_threshold': 3,
            'suspicious_usernames': ['admin', 'root', 'administrator', 'user', 'test']
        }
    
    def _init_malware_rules(self):
        """Initialize malware detection rules"""
        return {
            'suspicious_domains': [
                'bit.ly', 'tinyurl.com', 'goo.gl',  # URL shorteners
                '.tk', '.ml', '.cf', '.ga'           # Suspicious TLDs
            ],
            'c2_ports': [8080, 8443, 4444, 5555, 6666, 7777, 8888, 9999],
            'dns_tunneling_threshold': 100,  # DNS queries per minute
            'http_user_agents': [
                'wget', 'curl', 'python-requests', 'bot', 'scanner'
            ]
        }
    
    def _init_policy_violation_rules(self):
        """Initialize policy violation detection rules"""
        return {
            'blocked_protocols': ['torrent', 'p2p'],
            'blocked_ports': [6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889],
            'blocked_countries': ['CN', 'RU', 'KP', 'IR'],  # Country codes
            'max_download_size': 100 * 1024 * 1024,  # 100MB
            'business_hours_only': False,
            'allowed_subnets': ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']
        }
    
    def _init_suspicious_traffic_rules(self):
        """Initialize suspicious traffic detection rules"""
        return {
            'protocol_anomalies': {
                'tcp': {'flags': ['0x29', '0x3F']},  # Invalid flag combinations
                'icmp': {'types': [13, 14, 15, 16, 17, 18]},  # Timestamp, mask requests
                'ip': {'fragments': True, 'options': True}
            },
            'packet_size_anomalies': {
                'min_size': 64,
                'max_size': 1500,
                'suspicious_sizes': [0, 1, 64, 1500]  # Common attack sizes
            },
            'traffic_patterns': {
                'same_src_dst_ip': True,
                'reserved_ips': ['0.0.0.0', '255.255.255.255', '127.0.0.1'],
                'private_ip_leak': True
            }
        }
    
    def analyze_packet(self, packet_data):
        """
        Analyze packet against all rules
        
        Args:
            packet_data: Packet information dictionary
            
        Returns:
            list: List of detected violations
        """
        violations = []
        
        try:
            # Update tracking data
            self._update_tracking(packet_data)
            
            # Check each rule category
            for rule_category, rules in self.rules.items():
                violations.extend(self._check_rule_category(packet_data, rule_category, rules))
            
            # Log violations
            if violations:
                self.logger.warning(f"Rule violations detected: {len(violations)}")
                for violation in violations:
                    self.logger.warning(f"Violation: {violation['description']}")
            
            return violations
            
        except Exception as e:
            self.logger.error(f"Error analyzing packet: {str(e)}")
            return []
    
    def _update_tracking(self, packet_data):
        """Update tracking data structures"""
        src_ip = packet_data.get('src_ip', 'unknown')
        dst_ip = packet_data.get('dst_ip', 'unknown')
        src_port = packet_data.get('src_port', 0)
        dst_port = packet_data.get('dst_port', 0)
        protocol = packet_data.get('protocol', 'unknown')
        timestamp = packet_data.get('timestamp', datetime.now())
        
        # Update connection tracker
        conn_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
        self.connection_tracker[conn_key]['count'] += 1
        self.connection_tracker[conn_key]['timestamps'].append(timestamp)
        self.connection_tracker[conn_key]['ports'].add(dst_port)
        
        # Update IP tracker
        self.ip_tracker[src_ip]['connections'] += 1
        self.ip_tracker[src_ip]['unique_ports'].add(dst_port)
        if self.ip_tracker[src_ip]['first_seen'] is None:
            self.ip_tracker[src_ip]['first_seen'] = timestamp
        self.ip_tracker[src_ip]['last_seen'] = timestamp
        
        # Update protocol tracker
        self.protocol_tracker[protocol] += 1
    
    def _check_rule_category(self, packet_data, category, rules):
        """Check packet against specific rule category"""
        violations = []
        
        if category == 'port_scan':
            violations.extend(self._check_port_scan(packet_data, rules))
        elif category == 'ddos':
            violations.extend(self._check_ddos(packet_data, rules))
        elif category == 'brute_force':
            violations.extend(self._check_brute_force(packet_data, rules))
        elif category == 'malware':
            violations.extend(self._check_malware(packet_data, rules))
        elif category == 'policy_violation':
            violations.extend(self._check_policy_violation(packet_data, rules))
        elif category == 'suspicious_traffic':
            violations.extend(self._check_suspicious_traffic(packet_data, rules))
        
        return violations
    
    def _check_port_scan(self, packet_data, rules):
        """Check for port scanning activity"""
        violations = []
        src_ip = packet_data.get('src_ip', 'unknown')
        dst_port = packet_data.get('dst_port', 0)
        
        # Check if destination port is suspicious
        if dst_port in rules['suspicious_ports']:
            violations.append({
                'type': 'port_scan',
                'severity': 'medium',
                'description': f'Connection to suspicious port {dst_port} from {src_ip}',
                'confidence': 0.7
            })
        
        # Check for scan patterns
        for pattern in rules['scan_patterns']:
            if dst_port in pattern['ports']:
                # Check if this IP has connected to multiple ports in this pattern
                unique_ports = self.ip_tracker[src_ip]['unique_ports']
                pattern_ports_hit = len(unique_ports.intersection(set(pattern['ports'])))
                
                if pattern_ports_hit >= pattern['threshold']:
                    violations.append({
                        'type': 'port_scan',
                        'severity': 'high',
                        'description': f'Port scan pattern detected from {src_ip} ({pattern_ports_hit} ports)',
                        'confidence': 0.8
                    })
        
        # Check for rapid connections
        recent_connections = self._get_recent_connections(src_ip, rules['time_window'])
        if recent_connections >= rules['rapid_connection_threshold']:
            violations.append({
                'type': 'port_scan',
                'severity': 'high',
                'description': f'Rapid connections detected from {src_ip} ({recent_connections} in {rules["time_window"]}s)',
                'confidence': 0.9
            })
        
        return violations
    
    def _check_ddos(self, packet_data, rules):
        """Check for DDoS patterns"""
        violations = []
        dst_ip = packet_data.get('dst_ip', 'unknown')
        protocol = packet_data.get('protocol', 'unknown')
        flags = packet_data.get('flags', 0)
        
        # Check connection rate to destination IP
        recent_connections = self._get_recent_connections_to_dst(dst_ip, 60)  # 1 minute
        
        if recent_connections >= rules['connection_rate_threshold']:
            violations.append({
                'type': 'ddos',
                'severity': 'high',
                'description': f'High connection rate to {dst_ip} ({recent_connections}/min)',
                'confidence': 0.9
            })
        
        # Check for SYN flood
        if protocol == 'TCP' and (flags & 0x02):  # SYN flag
            syn_count = self._count_syn_packets_to_dst(dst_ip, 60)
            if syn_count >= rules['syn_flood_threshold']:
                violations.append({
                    'type': 'ddos',
                    'severity': 'high',
                    'description': f'SYN flood detected to {dst_ip} ({syn_count} SYNs/min)',
                    'confidence': 0.8
                })
        
        # Check for UDP flood
        if protocol == 'UDP':
            udp_count = self._count_protocol_packets_to_dst(dst_ip, 'UDP', 60)
            if udp_count >= rules['udp_flood_threshold']:
                violations.append({
                    'type': 'ddos',
                    'severity': 'high',
                    'description': f'UDP flood detected to {dst_ip} ({udp_count} UDPs/min)',
                    'confidence': 0.8
                })
        
        return violations
    
    def _check_brute_force(self, packet_data, rules):
        """Check for brute force patterns"""
        violations = []
        src_ip = packet_data.get('src_ip', 'unknown')
        dst_port = packet_data.get('dst_port', 0)
        
        # Check if destination port is commonly used for brute force
        if dst_port in rules['failed_login_ports']:
            # Check for repeated failed attempts (simulated)
            self.ip_tracker[src_ip]['failed_attempts'] += 1
            
            if self.ip_tracker[src_ip]['failed_attempts'] >= rules['failed_attempt_threshold']:
                violations.append({
                    'type': 'brute_force',
                    'severity': 'high',
                    'description': f'Brute force attack detected from {src_ip} on port {dst_port}',
                    'confidence': 0.8
                })
        
        return violations
    
    def _check_malware(self, packet_data, rules):
        """Check for malware indicators"""
        violations = []
        dst_port = packet_data.get('dst_port', 0)
        
        # Check for C2 communication ports
        if dst_port in rules['c2_ports']:
            violations.append({
                'type': 'malware',
                'severity': 'high',
                'description': f'Possible C2 communication on port {dst_port}',
                'confidence': 0.7
            })
        
        return violations
    
    def _check_policy_violation(self, packet_data, rules):
        """Check for policy violations"""
        violations = []
        dst_port = packet_data.get('dst_port', 0)
        protocol = packet_data.get('protocol', 'unknown')
        
        # Check for blocked ports
        if dst_port in rules['blocked_ports']:
            violations.append({
                'type': 'policy_violation',
                'severity': 'medium',
                'description': f'Connection to blocked port {dst_port}',
                'confidence': 0.9
            })
        
        return violations
    
    def _check_suspicious_traffic(self, packet_data, rules):
        """Check for suspicious traffic patterns"""
        violations = []
        src_ip = packet_data.get('src_ip', 'unknown')
        dst_ip = packet_data.get('dst_ip', 'unknown')
        protocol = packet_data.get('protocol', 'unknown')
        flags = packet_data.get('flags', 0)
        size = packet_data.get('size', 0)
        
        # Check for same source and destination IP
        if src_ip == dst_ip and rules['traffic_patterns']['same_src_dst_ip']:
            violations.append({
                'type': 'suspicious_traffic',
                'severity': 'medium',
                'description': f'Same source and destination IP: {src_ip}',
                'confidence': 0.8
            })
        
        # Check for reserved IPs
        if src_ip in rules['traffic_patterns']['reserved_ips'] or dst_ip in rules['traffic_patterns']['reserved_ips']:
            violations.append({
                'type': 'suspicious_traffic',
                'severity': 'medium',
                'description': f'Traffic involving reserved IP: {src_ip}->{dst_ip}',
                'confidence': 0.7
            })
        
        # Check for TCP flag anomalies
        if protocol == 'TCP':
            # Check for invalid flag combinations
            if flags == 0x29 or flags == 0x3F:  # Example invalid combinations
                violations.append({
                    'type': 'suspicious_traffic',
                    'severity': 'medium',
                    'description': f'Invalid TCP flag combination: 0x{flags:02X}',
                    'confidence': 0.8
                })
        
        # Check for suspicious packet sizes
        if size in rules['packet_size_anomalies']['suspicious_sizes']:
            violations.append({
                'type': 'suspicious_traffic',
                'severity': 'low',
                'description': f'Suspicious packet size: {size} bytes',
                'confidence': 0.6
            })
        
        return violations
    
    def _get_recent_connections(self, src_ip, time_window):
        """Get number of recent connections from source IP"""
        count = 0
        current_time = datetime.now()
        
        for conn_key, conn_data in self.connection_tracker.items():
            if conn_key.startswith(f"{src_ip}:"):
                # Count connections within time window
                for timestamp in conn_data['timestamps']:
                    if current_time - timestamp <= timedelta(seconds=time_window):
                        count += 1
        
        return count
    
    def _get_recent_connections_to_dst(self, dst_ip, time_window):
        """Get number of recent connections to destination IP"""
        count = 0
        current_time = datetime.now()
        
        for conn_key, conn_data in self.connection_tracker.items():
            if f"->{dst_ip}:" in conn_key:
                for timestamp in conn_data['timestamps']:
                    if current_time - timestamp <= timedelta(seconds=time_window):
                        count += 1
        
        return count
    
    def _count_syn_packets_to_dst(self, dst_ip, time_window):
        """Count SYN packets to destination"""
        # Simplified implementation
        return self._get_recent_connections_to_dst(dst_ip, time_window) // 2
    
    def _count_protocol_packets_to_dst(self, dst_ip, protocol, time_window):
        """Count packets of specific protocol to destination"""
        # Simplified implementation
        return self._get_recent_connections_to_dst(dst_ip, time_window) // 3
    
    def get_rule_statistics(self):
        """Get statistics about rule triggers"""
        stats = {
            'total_violations': 0,
            'violations_by_type': defaultdict(int),
            'top_offending_ips': [],
            'rule_effectiveness': {}
        }
        
        # This would track actual violations in a real implementation
        # For now, return basic structure
        return stats
    
    def update_rules(self, new_rules):
        """Update detection rules"""
        self.rules.update(new_rules)
        self.logger.info("Detection rules updated")
    
    def add_custom_rule(self, rule_name, rule_config):
        """Add custom detection rule"""
        self.rules[rule_name] = rule_config
        self.logger.info(f"Custom rule '{rule_name}' added")