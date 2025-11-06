import os
import logging
from datetime import datetime

# Network Configuration
NETWORK_INTERFACE = 'eth0'  # Change to your network interface
CAPTURE_DURATION = 60  # seconds
PACKET_BUFFER_SIZE = 1000

# ML Model Configuration
ML_MODELS = {
    'isolation_forest': {
        'contamination': 0.1,
        'n_estimators': 100,
        'max_samples': 'auto',
        'random_state': 42
    },
    'one_class_svm': {
        'kernel': 'rbf',
        'gamma': 'scale',
        'nu': 0.1
    },
    'random_forest': {
        'n_estimators': 100,
        'max_depth': 10,
        'random_state': 42
    }
}

# Rule-based Detection Thresholds
RULE_THRESHOLDS = {
    'port_scan_threshold': 10,  # Number of ports scanned from single IP
    'packet_size_threshold': 1500,  # Maximum normal packet size
    'connection_rate_threshold': 100,  # Connections per second
    'failed_connection_threshold': 5,  # Failed connections per IP
    'suspicious_payload_size': 1000,  # Payload size considered suspicious
}

# Alert Configuration
ALERT_SETTINGS = {
    'console_alerts': True,
    'log_to_file': True,
    'severity_levels': ['low', 'medium', 'high', 'critical'],
    'alert_cooldown': 5  # seconds between repeated alerts for same issue
}

# Data Storage Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
LOGS_DIR = os.path.join(BASE_DIR, 'logs')
MODELS_DIR = os.path.join(BASE_DIR, 'models')

# Create directories if they don't exist
for directory in [DATA_DIR, LOGS_DIR, MODELS_DIR]:
    os.makedirs(directory, exist_ok=True)
    os.makedirs(os.path.join(directory, 'captured_packets'), exist_ok=True)
    os.makedirs(os.path.join(directory, 'extracted_features'), exist_ok=True)
    os.makedirs(os.path.join(directory, 'detection_logs'), exist_ok=True)
    os.makedirs(os.path.join(directory, 'trained_models'), exist_ok=True)

# Logging Configuration
def setup_logging():
    """Setup logging configuration"""
    log_filename = f"ids_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    log_path = os.path.join(LOGS_DIR, 'detection_logs', log_filename)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_path),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

# Feature Extraction Configuration
FEATURES_LIST = [
    'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
    'packet_length', 'payload_length', 'time_delta', 'tcp_flags',
    'flow_duration', 'packet_count', 'byte_rate', 'packet_rate',
    'unique_ports', 'syn_count', 'ack_count', 'fin_count'
]

# Protocol Mapping
PROTOCOL_MAP = {
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP',
    2: 'IGMP',
    47: 'GRE',
    50: 'ESP',
    51: 'AH'
}

# Default thresholds for anomaly detection
ANOMALY_THRESHOLDS = {
    'z_score_threshold': 3.0,
    'iqr_multiplier': 1.5,
    'isolation_score_threshold': -0.2
}

# Web Dashboard Configuration
WEB_DASHBOARD = {
    'host': '127.0.0.1',
    'port': 5000,
    'debug': False,
    'update_interval': 1000  # milliseconds
}