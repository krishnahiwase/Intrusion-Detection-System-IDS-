"""
Sample Dataset Generator and Testing Utilities
Generates synthetic network traffic data for testing the IDS system
"""

import random
import ipaddress
import datetime
import json
import pandas as pd
import numpy as np
from typing import List, Dict, Any, Optional
import logging
import os

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SampleDatasetGenerator:
    """Generate synthetic network traffic data for testing"""
    
    def __init__(self):
        self.protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'FTP', 'SSH', 'DNS']
        self.normal_ports = [80, 443, 22, 21, 53, 110, 143, 25, 3389, 8080]
        self.suspicious_ports = [135, 139, 445, 1433, 1521, 3306, 5432, 27017]
        self.common_services = {
            80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 21: 'FTP', 53: 'DNS',
            110: 'POP3', 143: 'IMAP', 25: 'SMTP', 3389: 'RDP', 8080: 'HTTP-Proxy'
        }
        
        # IP ranges for different scenarios
        self.internal_networks = [
            '192.168.1.0/24', '10.0.0.0/16', '172.16.0.0/16'
        ]
        self.external_networks = [
            '203.0.113.0/24', '198.51.100.0/24', '192.0.2.0/24'
        ]
        
        # Attack patterns
        self.attack_patterns = {
            'port_scan': {
                'description': 'Port scanning activity',
                'severity': 'high',
                'ports': list(range(1, 1000)),
                'packet_rate': 50
            },
            'ddos': {
                'description': 'DDoS attack',
                'severity': 'critical',
                'packet_rate': 1000,
                'source_ips': 100
            },
            'brute_force': {
                'description': 'Brute force login attempt',
                'severity': 'high',
                'ports': [22, 3389, 21],
                'packet_rate': 20
            },
            'malware': {
                'description': 'Malware communication',
                'severity': 'critical',
                'ports': [6667, 8080, 9999],
                'packet_rate': 5
            }
        }
    
    def generate_normal_traffic(self, num_packets: int = 1000) -> List[Dict[str, Any]]:
        """Generate normal network traffic"""
        logger.info(f"Generating {num_packets} normal traffic packets...")
        
        packets = []
        start_time = datetime.datetime.now() - datetime.timedelta(hours=1)
        
        for i in range(num_packets):
            # Generate random time within the last hour
            timestamp = start_time + datetime.timedelta(
                seconds=random.randint(0, 3600)
            )
            
            # Generate internal IPs
            internal_ip = self._generate_internal_ip()
            external_ip = self._generate_external_ip()
            
            # Random packet direction (internal -> external or vice versa)
            if random.random() > 0.5:
                src_ip = internal_ip
                dst_ip = external_ip
            else:
                src_ip = external_ip
                dst_ip = internal_ip
            
            # Generate packet data
            packet = {
                'timestamp': timestamp.isoformat(),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': random.choice(self.normal_ports) if random.random() > 0.3 else random.randint(1024, 65535),
                'dst_port': random.choice(self.normal_ports),
                'protocol': random.choice(['TCP', 'UDP']),
                'packet_size': random.randint(64, 1500),
                'flags': self._generate_tcp_flags(normal=True),
                'ttl': random.randint(64, 128),
                'flow_duration': random.randint(1, 300),
                'packet_rate': random.randint(1, 50),
                'byte_rate': random.randint(100, 10000),
                'label': 'normal'
            }
            
            packets.append(packet)
        
        logger.info(f"Generated {len(packets)} normal traffic packets")
        return packets
    
    def generate_malicious_traffic(self, num_packets: int = 200) -> List[Dict[str, Any]]:
        """Generate malicious network traffic"""
        logger.info(f"Generating {num_packets} malicious traffic packets...")
        
        packets = []
        start_time = datetime.datetime.now() - datetime.timedelta(minutes=30)
        
        # Different attack types
        attack_types = list(self.attack_patterns.keys())
        
        for i in range(num_packets):
            attack_type = random.choice(attack_types)
            pattern = self.attack_patterns[attack_type]
            
            # Generate timestamp (more recent for attacks)
            timestamp = start_time + datetime.timedelta(
                seconds=random.randint(0, 1800)
            )
            
            # Generate attack-specific IPs
            src_ip = self._generate_external_ip()
            dst_ip = self._generate_internal_ip()
            
            # Generate attack-specific packet
            if attack_type == 'port_scan':
                packet = self._generate_port_scan_packet(timestamp, src_ip, dst_ip, pattern)
            elif attack_type == 'ddos':
                packet = self._generate_ddos_packet(timestamp, src_ip, dst_ip, pattern)
            elif attack_type == 'brute_force':
                packet = self._generate_brute_force_packet(timestamp, src_ip, dst_ip, pattern)
            elif attack_type == 'malware':
                packet = self._generate_malware_packet(timestamp, src_ip, dst_ip, pattern)
            else:
                packet = self._generate_generic_attack_packet(timestamp, src_ip, dst_ip, pattern)
            
            packets.append(packet)
        
        logger.info(f"Generated {len(packets)} malicious traffic packets")
        return packets
    
    def generate_mixed_dataset(self, normal_ratio: float = 0.8, total_packets: int = 1200) -> List[Dict[str, Any]]:
        """Generate mixed dataset with normal and malicious traffic"""
        logger.info(f"Generating mixed dataset with {normal_ratio*100}% normal traffic...")
        
        num_normal = int(total_packets * normal_ratio)
        num_malicious = total_packets - num_normal
        
        normal_packets = self.generate_normal_traffic(num_normal)
        malicious_packets = self.generate_malicious_traffic(num_malicious)
        
        # Combine and shuffle
        all_packets = normal_packets + malicious_packets
        random.shuffle(all_packets)
        
        logger.info(f"Generated mixed dataset with {len(all_packets)} packets")
        return all_packets
    
    def _generate_internal_ip(self) -> str:
        """Generate random internal IP address"""
        network = random.choice(self.internal_networks)
        net = ipaddress.ip_network(network)
        # Exclude network and broadcast addresses
        host = random.randint(1, net.num_addresses - 2)
        return str(net.network_address + host)
    
    def _generate_external_ip(self) -> str:
        """Generate random external IP address"""
        network = random.choice(self.external_networks)
        net = ipaddress.ip_network(network)
        host = random.randint(1, net.num_addresses - 2)
        return str(net.network_address + host)
    
    def _generate_tcp_flags(self, normal: bool = True) -> str:
        """Generate TCP flags"""
        if normal:
            return random.choice(['SYN', 'ACK', 'PSH+ACK', 'FIN+ACK'])
        else:
            return random.choice(['SYN', 'FIN', 'RST', 'PSH+URG'])
    
    def _generate_port_scan_packet(self, timestamp: datetime.datetime, src_ip: str, dst_ip: str, pattern: Dict) -> Dict[str, Any]:
        """Generate port scan packet"""
        return {
            'timestamp': timestamp.isoformat(),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': random.randint(1024, 65535),
            'dst_port': random.choice(pattern['ports']),
            'protocol': 'TCP',
            'packet_size': random.randint(40, 100),
            'flags': 'SYN',
            'ttl': random.randint(64, 128),
            'flow_duration': random.randint(1, 5),
            'packet_rate': pattern['packet_rate'],
            'byte_rate': random.randint(1000, 5000),
            'label': 'port_scan',
            'attack_type': 'port_scan',
            'severity': pattern['severity']
        }
    
    def _generate_ddos_packet(self, timestamp: datetime.datetime, src_ip: str, dst_ip: str, pattern: Dict) -> Dict[str, Any]:
        """Generate DDoS packet"""
        # Vary source IP for DDoS simulation
        src_ip = self._generate_external_ip()
        
        return {
            'timestamp': timestamp.isoformat(),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': random.randint(1024, 65535),
            'dst_port': random.choice([80, 443]),
            'protocol': random.choice(['TCP', 'UDP']),
            'packet_size': random.randint(1000, 1500),
            'flags': random.choice(['SYN', 'ACK']),
            'ttl': random.randint(64, 128),
            'flow_duration': random.randint(1, 10),
            'packet_rate': pattern['packet_rate'],
            'byte_rate': random.randint(50000, 100000),
            'label': 'ddos',
            'attack_type': 'ddos',
            'severity': pattern['severity']
        }
    
    def _generate_brute_force_packet(self, timestamp: datetime.datetime, src_ip: str, dst_ip: str, pattern: Dict) -> Dict[str, Any]:
        """Generate brute force packet"""
        return {
            'timestamp': timestamp.isoformat(),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': random.randint(1024, 65535),
            'dst_port': random.choice(pattern['ports']),
            'protocol': 'TCP',
            'packet_size': random.randint(60, 200),
            'flags': random.choice(['SYN', 'PSH+ACK']),
            'ttl': random.randint(64, 128),
            'flow_duration': random.randint(5, 60),
            'packet_rate': pattern['packet_rate'],
            'byte_rate': random.randint(500, 2000),
            'label': 'brute_force',
            'attack_type': 'brute_force',
            'severity': pattern['severity']
        }
    
    def _generate_malware_packet(self, timestamp: datetime.datetime, src_ip: str, dst_ip: str, pattern: Dict) -> Dict[str, Any]:
        """Generate malware communication packet"""
        return {
            'timestamp': timestamp.isoformat(),
            'src_ip': dst_ip,  # Internal host communicating out
            'dst_ip': self._generate_external_ip(),
            'src_port': random.randint(1024, 65535),
            'dst_port': random.choice(pattern['ports']),
            'protocol': random.choice(['TCP', 'UDP']),
            'packet_size': random.randint(100, 500),
            'flags': 'PSH+ACK',
            'ttl': random.randint(64, 128),
            'flow_duration': random.randint(10, 300),
            'packet_rate': pattern['packet_rate'],
            'byte_rate': random.randint(100, 1000),
            'label': 'malware',
            'attack_type': 'malware',
            'severity': pattern['severity']
        }
    
    def _generate_generic_attack_packet(self, timestamp: datetime.datetime, src_ip: str, dst_ip: str, pattern: Dict) -> Dict[str, Any]:
        """Generate generic attack packet"""
        return {
            'timestamp': timestamp.isoformat(),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': random.randint(1024, 65535),
            'dst_port': random.choice(self.suspicious_ports),
            'protocol': random.choice(['TCP', 'UDP']),
            'packet_size': random.randint(40, 1500),
            'flags': self._generate_tcp_flags(normal=False),
            'ttl': random.randint(32, 64),
            'flow_duration': random.randint(1, 30),
            'packet_rate': random.randint(10, 100),
            'byte_rate': random.randint(500, 5000),
            'label': 'attack',
            'attack_type': 'generic',
            'severity': 'medium'
        }
    
    def save_to_csv(self, packets: List[Dict[str, Any]], filename: str):
        """Save packets to CSV file"""
        try:
            df = pd.DataFrame(packets)
            df.to_csv(filename, index=False)
            logger.info(f"Saved {len(packets)} packets to {filename}")
            return True
        except Exception as e:
            logger.error(f"Error saving to CSV: {str(e)}")
            return False
    
    def save_to_json(self, packets: List[Dict[str, Any]], filename: str):
        """Save packets to JSON file"""
        try:
            with open(filename, 'w') as f:
                json.dump(packets, f, indent=2, default=str)
            logger.info(f"Saved {len(packets)} packets to {filename}")
            return True
        except Exception as e:
            logger.error(f"Error saving to JSON: {str(e)}")
            return False

class TestingUtilities:
    """Utilities for testing the IDS system"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def create_test_pcap(self, packets: List[Dict[str, Any]], filename: str):
        """Create a test PCAP file (simulated)"""
        try:
            # Since we can't easily create actual PCAP without scapy writing capabilities,
            # we'll create a JSON representation that can be loaded by our packet capture
            test_data = {
                'metadata': {
                    'created': datetime.datetime.now().isoformat(),
                    'packet_count': len(packets),
                    'description': 'Test dataset for IDS'
                },
                'packets': packets
            }
            
            with open(filename, 'w') as f:
                json.dump(test_data, f, indent=2, default=str)
            
            logger.info(f"Created test dataset: {filename}")
            return True
            
        except Exception as e:
            logger.error(f"Error creating test dataset: {str(e)}")
            return False
    
    def validate_dataset(self, packets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Validate dataset quality and completeness"""
        validation_results = {
            'total_packets': len(packets),
            'valid_packets': 0,
            'missing_fields': {},
            'label_distribution': {},
            'time_range': None,
            'validation_passed': False
        }
        
        try:
            if not packets:
                return validation_results
            
            required_fields = [
                'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
                'protocol', 'packet_size', 'label'
            ]
            
            valid_packets = 0
            timestamps = []
            
            for packet in packets:
                packet_valid = True
                
                # Check required fields
                for field in required_fields:
                    if field not in packet or packet[field] is None:
                        packet_valid = False
                        if field not in validation_results['missing_fields']:
                            validation_results['missing_fields'][field] = 0
                        validation_results['missing_fields'][field] += 1
                
                if packet_valid:
                    valid_packets += 1
                    
                    # Collect label distribution
                    label = packet.get('label', 'unknown')
                    validation_results['label_distribution'][label] = \
                        validation_results['label_distribution'].get(label, 0) + 1
                    
                    # Collect timestamps
                    try:
                        timestamp = datetime.datetime.fromisoformat(packet['timestamp'])
                        timestamps.append(timestamp)
                    except:
                        pass
            
            validation_results['valid_packets'] = valid_packets
            
            # Calculate time range
            if timestamps:
                validation_results['time_range'] = {
                    'start': min(timestamps).isoformat(),
                    'end': max(timestamps).isoformat(),
                    'duration': (max(timestamps) - min(timestamps)).total_seconds()
                }
            
            # Validation criteria
            validation_results['validation_passed'] = (
                valid_packets > len(packets) * 0.95 and  # 95% valid packets
                len(validation_results['missing_fields']) <= 2 and
                len(validation_results['label_distribution']) >= 2  # At least 2 different labels
            )
            
        except Exception as e:
            logger.error(f"Error validating dataset: {str(e)}")
            validation_results['error'] = str(e)
        
        return validation_results
    
    def generate_feature_dataset(self, packets: List[Dict[str, Any]]) -> pd.DataFrame:
        """Generate feature dataset from packet data"""
        try:
            # Convert to DataFrame
            df = pd.DataFrame(packets)
            
            # Add derived features
            df['hour'] = pd.to_datetime(df['timestamp']).dt.hour
            df['day_of_week'] = pd.to_datetime(df['timestamp']).dt.dayofweek
            
            # Port-based features
            df['is_well_known_port'] = df['dst_port'].isin([80, 443, 22, 21, 53, 25, 110, 143])
            df['is_suspicious_port'] = df['dst_port'].isin([135, 139, 445, 1433, 1521, 3306])
            
            # Traffic-based features
            df['packet_rate_category'] = pd.cut(df['packet_rate'], 
                                                bins=[0, 10, 50, 100, float('inf')], 
                                                labels=['low', 'medium', 'high', 'extreme'])
            
            # Protocol features
            df['is_encrypted'] = df['protocol'].isin(['HTTPS', 'SSH'])
            df['is_web_traffic'] = df['dst_port'].isin([80, 443, 8080])
            
            logger.info(f"Generated feature dataset with {len(df)} samples and {len(df.columns)} features")
            return df
            
        except Exception as e:
            logger.error(f"Error generating feature dataset: {str(e)}")
            return pd.DataFrame()

def main():
    """Main function to generate sample datasets"""
    try:
        # Create dataset generator
        generator = SampleDatasetGenerator()
        tester = TestingUtilities()
        
        # Create output directory
        os.makedirs('sample_data', exist_ok=True)
        
        # Generate different types of datasets
        datasets = {
            'normal_traffic': generator.generate_normal_traffic(1000),
            'malicious_traffic': generator.generate_malicious_traffic(200),
            'mixed_traffic': generator.generate_mixed_dataset(normal_ratio=0.8, total_packets=1200)
        }
        
        # Save datasets
        for name, data in datasets.items():
            # Save as JSON
            json_file = f'sample_data/{name}.json'
            generator.save_to_json(data, json_file)
            
            # Save as CSV
            csv_file = f'sample_data/{name}.csv'
            generator.save_to_csv(data, csv_file)
            
            # Validate dataset
            validation = tester.validate_dataset(data)
            
            # Generate feature dataset
            feature_df = tester.generate_feature_dataset(data)
            feature_file = f'sample_data/{name}_features.csv'
            feature_df.to_csv(feature_file, index=False)
            
            # Print validation results
            logger.info(f"\n=== Dataset: {name} ===")
            logger.info(f"Total packets: {validation['total_packets']}")
            logger.info(f"Valid packets: {validation['valid_packets']}")
            logger.info(f"Label distribution: {validation['label_distribution']}")
            logger.info(f"Validation passed: {validation['validation_passed']}")
            
            if validation['missing_fields']:
                logger.warning(f"Missing fields: {validation['missing_fields']}")
        
        # Create test PCAP files (JSON format)
        for name, data in datasets.items():
            pcap_file = f'sample_data/{name}_test.pcap.json'
            tester.create_test_pcap(data, pcap_file)
        
        logger.info("\nSample datasets generated successfully!")
        logger.info("Files created in 'sample_data' directory:")
        for file in os.listdir('sample_data'):
            logger.info(f"  - {file}")
        
    except Exception as e:
        logger.error(f"Error in main function: {str(e)}")

if __name__ == '__main__':
    main()