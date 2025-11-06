"""
Feature Extraction Module
Extracts relevant features from network packets for ML analysis
"""

import logging
import numpy as np
import pandas as pd
from datetime import datetime
from collections import defaultdict
from config import FEATURES_LIST, PROTOCOL_MAP

class FeatureExtractor:
    """Extract features from network packets for anomaly detection"""
    
    def __init__(self):
        """Initialize feature extractor"""
        self.logger = logging.getLogger(__name__)
        self.flow_tracker = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'end_time': None,
            'ports': set(),
            'flags': defaultdict(int)
        })
        
        # Feature definitions
        self.feature_definitions = {
            'basic_features': [
                'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
                'packet_length', 'payload_length'
            ],
            'temporal_features': [
                'time_delta', 'flow_duration', 'packet_rate', 'byte_rate'
            ],
            'behavioral_features': [
                'packet_count', 'unique_ports', 'syn_count', 'ack_count', 'fin_count'
            ],
            'derived_features': [
                'port_class', 'protocol_type', 'is_private_ip', 'is_well_known_port'
            ]
        }
    
    def extract_features(self, packets):
        """
        Extract features from list of packets
        
        Args:
            packets: List of packet dictionaries
            
        Returns:
            pd.DataFrame: Extracted features
        """
        self.logger.info(f"Extracting features from {len(packets)} packets")
        
        if not packets:
            return pd.DataFrame()
        
        features_list = []
        
        for i, packet in enumerate(packets):
            try:
                features = self.extract_packet_features(packet, i)
                features_list.append(features)
            except Exception as e:
                self.logger.error(f"Error extracting features from packet {i}: {str(e)}")
                continue
        
        # Convert to DataFrame
        features_df = pd.DataFrame(features_list)
        
        # Fill missing values
        features_df = features_df.fillna(0)
        
        self.logger.info(f"Extracted {len(features_df.columns)} features from {len(features_df)} packets")
        return features_df
    
    def extract_packet_features(self, packet, index):
        """
        Extract features from a single packet
        
        Args:
            packet: Single packet dictionary
            index: Packet index in the sequence
            
        Returns:
            dict: Extracted features
        """
        features = {}
        
        # Basic features
        features.update(self._extract_basic_features(packet))
        
        # Temporal features
        features.update(self._extract_temporal_features(packet, index))
        
        # Behavioral features
        features.update(self._extract_behavioral_features(packet))
        
        # Derived features
        features.update(self._extract_derived_features(features))
        
        return features
    
    def _extract_basic_features(self, packet):
        """Extract basic packet features"""
        features = {}
        
        # IP addresses
        features['src_ip'] = packet.get('src_ip', '0.0.0.0')
        features['dst_ip'] = packet.get('dst_ip', '0.0.0.0')
        
        # Ports
        features['src_port'] = packet.get('src_port', 0)
        features['dst_port'] = packet.get('dst_port', 0)
        
        # Protocol
        protocol = packet.get('protocol', 'Unknown')
        if isinstance(protocol, int):
            features['protocol'] = PROTOCOL_MAP.get(protocol, 'Unknown')
        else:
            features['protocol'] = protocol
        
        # Packet size
        features['packet_length'] = packet.get('size', 0)
        features['payload_length'] = packet.get('payload_size', 0)
        
        # TCP flags
        flags = packet.get('flags', 0)
        if isinstance(flags, int):
            features['tcp_flags'] = flags
        else:
            features['tcp_flags'] = self._parse_tcp_flags(flags)
        
        return features
    
    def _extract_temporal_features(self, packet, index):
        """Extract temporal features"""
        features = {}
        
        # Time delta (placeholder - would need actual timestamps)
        features['time_delta'] = 0.1  # Default small value
        
        # Flow tracking
        flow_key = self._get_flow_key(packet)
        flow_info = self.flow_tracker[flow_key]
        
        # Update flow information
        current_time = datetime.now()
        if flow_info['start_time'] is None:
            flow_info['start_time'] = current_time
        flow_info['end_time'] = current_time
        
        # Calculate flow duration
        if flow_info['start_time'] and flow_info['end_time']:
            duration = (flow_info['end_time'] - flow_info['start_time']).total_seconds()
            features['flow_duration'] = max(duration, 0.001)  # Minimum 1ms
        else:
            features['flow_duration'] = 0.001
        
        # Calculate rates
        if features['flow_duration'] > 0:
            features['packet_rate'] = flow_info['packet_count'] / features['flow_duration']
            features['byte_rate'] = flow_info['byte_count'] / features['flow_duration']
        else:
            features['packet_rate'] = 0
            features['byte_rate'] = 0
        
        return features
    
    def _extract_behavioral_features(self, packet):
        """Extract behavioral features"""
        features = {}
        
        flow_key = self._get_flow_key(packet)
        flow_info = self.flow_tracker[flow_key]
        
        # Update flow counters
        flow_info['packet_count'] += 1
        flow_info['byte_count'] += packet.get('size', 0)
        flow_info['ports'].add(packet.get('src_port', 0))
        flow_info['ports'].add(packet.get('dst_port', 0))
        
        # TCP flag counts
        flags = packet.get('flags', 0)
        if isinstance(flags, int):
            if flags & 0x02:  # SYN flag
                flow_info['flags']['syn'] += 1
            if flags & 0x10:  # ACK flag
                flow_info['flags']['ack'] += 1
            if flags & 0x01:  # FIN flag
                flow_info['flags']['fin'] += 1
        
        # Extract features
        features['packet_count'] = flow_info['packet_count']
        features['unique_ports'] = len(flow_info['ports'])
        features['syn_count'] = flow_info['flags']['syn']
        features['ack_count'] = flow_info['flags']['ack']
        features['fin_count'] = flow_info['flags']['fin']
        
        return features
    
    def _extract_derived_features(self, basic_features):
        """Extract derived features"""
        features = {}
        
        # Port classification
        src_port = basic_features.get('src_port', 0)
        dst_port = basic_features.get('dst_port', 0)
        
        features['port_class'] = self._classify_port(max(src_port, dst_port))
        
        # Protocol type encoding
        protocol = basic_features.get('protocol', 'Unknown')
        features['protocol_type'] = self._encode_protocol(protocol)
        
        # IP classification
        src_ip = basic_features.get('src_ip', '0.0.0.0')
        dst_ip = basic_features.get('dst_ip', '0.0.0.0')
        
        features['is_private_ip'] = self._is_private_ip(src_ip) or self._is_private_ip(dst_ip)
        features['is_well_known_port'] = self._is_well_known_port(src_port) or self._is_well_known_port(dst_port)
        
        return features
    
    def _get_flow_key(self, packet):
        """Generate flow key for tracking"""
        src_ip = packet.get('src_ip', '0.0.0.0')
        dst_ip = packet.get('dst_ip', '0.0.0.0')
        src_port = packet.get('src_port', 0)
        dst_port = packet.get('dst_port', 0)
        protocol = packet.get('protocol', 'Unknown')
        
        # Create bidirectional flow key
        if src_ip < dst_ip:
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}:{protocol}"
        else:
            return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}:{protocol}"
    
    def _parse_tcp_flags(self, flags):
        """Parse TCP flags"""
        if isinstance(flags, str):
            flag_map = {'F': 1, 'S': 2, 'R': 4, 'P': 8, 'A': 16, 'U': 32}
            flag_value = 0
            for flag in flags:
                if flag in flag_map:
                    flag_value |= flag_map[flag]
            return flag_value
        return 0
    
    def _classify_port(self, port):
        """Classify port number"""
        if 0 <= port <= 1023:
            return 'well_known'
        elif 1024 <= port <= 49151:
            return 'registered'
        elif 49152 <= port <= 65535:
            return 'dynamic'
        else:
            return 'invalid'
    
    def _encode_protocol(self, protocol):
        """Encode protocol as numeric value"""
        protocol_map = {'TCP': 1, 'UDP': 2, 'ICMP': 3, 'ARP': 4, 'Unknown': 0}
        return protocol_map.get(protocol, 0)
    
    def _is_private_ip(self, ip):
        """Check if IP address is private"""
        if not ip or ip == '0.0.0.0':
            return False
        
        private_ranges = [
            '10.0.0.0/8',
            '172.16.0.0/12',
            '192.168.0.0/16',
            '127.0.0.0/8'
        ]
        
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            for range_str in private_ranges:
                if ip_obj in ipaddress.ip_network(range_str):
                    return True
            return False
        except:
            return False
    
    def _is_well_known_port(self, port):
        """Check if port is well-known"""
        well_known_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]
        return port in well_known_ports
    
    def get_feature_importance(self, features_df, target_column='is_anomaly'):
        """
        Calculate feature importance using correlation
        
        Args:
            features_df: DataFrame with features
            target_column: Target column name
            
        Returns:
            dict: Feature importance scores
        """
        try:
            numeric_features = features_df.select_dtypes(include=[np.number])
            if target_column in numeric_features.columns:
                correlations = numeric_features.corr()[target_column].abs()
                return correlations.to_dict()
            else:
                return {}
        except Exception as e:
            self.logger.error(f"Error calculating feature importance: {str(e)}")
            return {}
    
    def normalize_features(self, features_df):
        """
        Normalize features for ML processing
        
        Args:
            features_df: DataFrame with features
            
        Returns:
            pd.DataFrame: Normalized features
        """
        try:
            from sklearn.preprocessing import StandardScaler
            
            # Separate numeric and categorical features
            numeric_features = features_df.select_dtypes(include=[np.number])
            categorical_features = features_df.select_dtypes(exclude=[np.number])
            
            # Normalize numeric features
            scaler = StandardScaler()
            normalized_numeric = pd.DataFrame(
                scaler.fit_transform(numeric_features),
                columns=numeric_features.columns,
                index=numeric_features.index
            )
            
            # Combine with categorical features
            normalized_df = pd.concat([normalized_numeric, categorical_features], axis=1)
            
            return normalized_df
            
        except ImportError:
            self.logger.warning("sklearn not available, returning original features")
            return features_df
        except Exception as e:
            self.logger.error(f"Error normalizing features: {str(e)}")
            return features_df
    
    def save_features(self, features_df, filename):
        """Save extracted features to file"""
        try:
            features_df.to_csv(filename, index=False)
            self.logger.info(f"Features saved to {filename}")
        except Exception as e:
            self.logger.error(f"Error saving features: {str(e)}")
    
    def load_features(self, filename):
        """Load features from file"""
        try:
            features_df = pd.read_csv(filename)
            self.logger.info(f"Features loaded from {filename}")
            return features_df
        except Exception as e:
            self.logger.error(f"Error loading features: {str(e)}")
            return pd.DataFrame()