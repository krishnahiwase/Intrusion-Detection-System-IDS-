"""
Real-time Detection and Alerting System
Handles real-time anomaly detection and generates alerts
"""

import logging
import json
import time
import smtplib
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import defaultdict, deque
import threading
from typing import List, Dict, Optional
from config import ALERT_CONFIG, LOGGING_CONFIG

class AlertManager:
    """Manages alerts and notifications for detected anomalies"""
    
    def __init__(self, config=None):
        """
        Initialize alert manager
        
        Args:
            config: Alert configuration dictionary
        """
        self.logger = logging.getLogger(__name__)
        self.config = config or ALERT_CONFIG
        
        # Alert tracking
        self.alert_history = deque(maxlen=self.config.get('max_alerts_history', 1000))
        self.alert_counts = defaultdict(int)
        self.last_alert_time = defaultdict(float)
        
        # Rate limiting
        self.rate_limit_window = self.config.get('rate_limit_window', 60)  # seconds
        self.max_alerts_per_window = self.config.get('max_alerts_per_type', 10)
        
        # Alert thresholds
        self.severity_thresholds = self.config.get('severity_thresholds', {
            'low': 0.3,
            'medium': 0.6,
            'high': 0.8
        })
        
        # Initialize alert handlers
        self.handlers = {
            'console': ConsoleAlertHandler(),
            'file': FileAlertHandler(self.config.get('log_file', 'logs/alerts.log')),
            'email': EmailAlertHandler(self.config.get('email_config', {}))
        }
        
        self.logger.info("Alert manager initialized")
    
    def create_alert(self, anomaly_data, packet_info=None, confidence=0.0):
        """
        Create and process an alert
        
        Args:
            anomaly_data: Anomaly detection results
            packet_info: Original packet information
            confidence: Confidence score (0-1)
            
        Returns:
            dict: Alert information
        """
        try:
            alert = {
                'id': self._generate_alert_id(),
                'timestamp': datetime.now(),
                'severity': self._determine_severity(confidence),
                'confidence': confidence,
                'anomaly_type': self._determine_anomaly_type(anomaly_data),
                'packet_info': packet_info,
                'anomaly_data': anomaly_data,
                'description': self._generate_description(anomaly_data, packet_info)
            }
            
            # Check rate limiting
            if self._check_rate_limit(alert['anomaly_type']):
                self._process_alert(alert)
                self.alert_history.append(alert)
                self.alert_counts[alert['anomaly_type']] += 1
                
                self.logger.warning(f"Alert created: {alert['description']}")
                return alert
            else:
                self.logger.debug(f"Alert rate limited: {alert['anomaly_type']}")
                return None
                
        except Exception as e:
            self.logger.error(f"Error creating alert: {str(e)}")
            return None
    
    def _generate_alert_id(self):
        """Generate unique alert ID"""
        return f"alert_{int(time.time() * 1000)}"
    
    def _determine_severity(self, confidence):
        """Determine alert severity based on confidence"""
        if confidence >= self.severity_thresholds['high']:
            return 'high'
        elif confidence >= self.severity_thresholds['medium']:
            return 'medium'
        else:
            return 'low'
    
    def _determine_anomaly_type(self, anomaly_data):
        """Determine type of anomaly"""
        # This is a simplified classification
        # In a real system, you'd have more sophisticated classification
        
        if isinstance(anomaly_data, dict):
            if 'port_scan' in str(anomaly_data).lower():
                return 'port_scan'
            elif 'ddos' in str(anomaly_data).lower():
                return 'ddos'
            elif 'brute_force' in str(anomaly_data).lower():
                return 'brute_force'
        
        return 'unknown_anomaly'
    
    def _generate_description(self, anomaly_data, packet_info):
        """Generate human-readable alert description"""
        try:
            if packet_info:
                src_ip = packet_info.get('src_ip', 'unknown')
                dst_ip = packet_info.get('dst_ip', 'unknown')
                protocol = packet_info.get('protocol', 'unknown')
                
                return f"Suspicious {protocol} traffic from {src_ip} to {dst_ip}"
            else:
                return f"Network anomaly detected: {str(anomaly_data)[:100]}"
                
        except Exception:
            return "Network anomaly detected"
    
    def _check_rate_limit(self, alert_type):
        """Check if alert should be rate limited"""
        current_time = time.time()
        time_since_last = current_time - self.last_alert_time[alert_type]
        
        if time_since_last < self.rate_limit_window:
            # Check if we've exceeded the limit in the current window
            if self.alert_counts[alert_type] >= self.max_alerts_per_window:
                return False
        else:
            # Reset counter for new window
            self.alert_counts[alert_type] = 0
        
        self.last_alert_time[alert_type] = current_time
        return True
    
    def _process_alert(self, alert):
        """Process alert through configured handlers"""
        handlers_to_use = self.config.get('alert_handlers', ['console', 'file'])
        
        for handler_name in handlers_to_use:
            if handler_name in self.handlers:
                try:
                    self.handlers[handler_name].send_alert(alert)
                except Exception as e:
                    self.logger.error(f"Error in alert handler {handler_name}: {str(e)}")
    
    def get_recent_alerts(self, count=10, severity=None):
        """
        Get recent alerts
        
        Args:
            count: Number of alerts to return
            severity: Filter by severity level
            
        Returns:
            list: Recent alerts
        """
        alerts = list(self.alert_history)
        
        if severity:
            alerts = [alert for alert in alerts if alert['severity'] == severity]
        
        return alerts[-count:] if count > 0 else alerts
    
    def get_alert_statistics(self):
        """Get alert statistics"""
        stats = {
            'total_alerts': len(self.alert_history),
            'alerts_by_type': dict(self.alert_counts),
            'alerts_by_severity': defaultdict(int)
        }
        
        for alert in self.alert_history:
            stats['alerts_by_severity'][alert['severity']] += 1
        
        stats['alerts_by_severity'] = dict(stats['alerts_by_severity'])
        return stats
    
    def clear_alerts(self):
        """Clear alert history"""
        self.alert_history.clear()
        self.alert_counts.clear()
        self.last_alert_time.clear()
        self.logger.info("Alert history cleared")


class ConsoleAlertHandler:
    """Console alert handler"""
    
    def send_alert(self, alert):
        """Send alert to console"""
        print(f"\n{'='*60}")
        print(f"SECURITY ALERT - {alert['severity'].upper()}")
        print(f"{'='*60}")
        print(f"Time: {alert['timestamp']}")
        print(f"Type: {alert['anomaly_type']}")
        print(f"Confidence: {alert['confidence']:.2f}")
        print(f"Description: {alert['description']}")
        if alert['packet_info']:
            print(f"Source: {alert['packet_info'].get('src_ip', 'N/A')}")
            print(f"Destination: {alert['packet_info'].get('dst_ip', 'N/A')}")
        print(f"{'='*60}\n")


class FileAlertHandler:
    """File-based alert handler"""
    
    def __init__(self, log_file):
        self.log_file = log_file
        # Ensure directory exists
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
    
    def send_alert(self, alert):
        """Write alert to file"""
        try:
            with open(self.log_file, 'a') as f:
                alert_json = {
                    'timestamp': alert['timestamp'].isoformat(),
                    'severity': alert['severity'],
                    'type': alert['anomaly_type'],
                    'confidence': alert['confidence'],
                    'description': alert['description'],
                    'packet_info': alert.get('packet_info', {})
                }
                f.write(json.dumps(alert_json) + '\n')
        except Exception as e:
            logging.getLogger(__name__).error(f"Error writing alert to file: {str(e)}")


class EmailAlertHandler:
    """Email alert handler"""
    
    def __init__(self, email_config):
        self.config = email_config
        self.enabled = email_config.get('enabled', False)
    
    def send_alert(self, alert):
        """Send alert via email"""
        if not self.enabled:
            return
        
        try:
            msg = MIMEMultipart()
            msg['From'] = self.config['from_email']
            msg['To'] = self.config['to_email']
            msg['Subject'] = f"IDS Alert - {alert['severity'].upper()}: {alert['anomaly_type']}"
            
            body = f"""
            Security Alert Generated by Network IDS
            
            Timestamp: {alert['timestamp']}
            Severity: {alert['severity'].upper()}
            Type: {alert['anomaly_type']}
            Confidence: {alert['confidence']:.2f}
            
            Description: {alert['description']}
            
            Packet Information:
            {json.dumps(alert.get('packet_info', {}), indent=2)}
            
            Anomaly Data:
            {json.dumps(alert.get('anomaly_data', {}), indent=2)}
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email (simplified - in production, use proper SMTP setup)
            # This is a placeholder implementation
            self.logger.info(f"Email alert would be sent: {msg['Subject']}")
            
        except Exception as e:
            logging.getLogger(__name__).error(f"Error sending email alert: {str(e)}")


class RealtimeDetector:
    """Real-time anomaly detection system"""
    
    def __init__(self, anomaly_detector, alert_manager, window_size=100):
        """
        Initialize real-time detector
        
        Args:
            anomaly_detector: Trained anomaly detection model
            alert_manager: Alert manager instance
            window_size: Size of sliding window for detection
        """
        self.logger = logging.getLogger(__name__)
        self.anomaly_detector = anomaly_detector
        self.alert_manager = alert_manager
        self.window_size = window_size
        
        # Real-time tracking
        self.packet_buffer = deque(maxlen=window_size)
        self.detection_thread = None
        self.running = False
        self.detection_interval = 5  # seconds
        
        # Statistics
        self.packets_processed = 0
        self.anomalies_detected = 0
        self.start_time = None
        
        self.logger.info("Real-time detector initialized")
    
    def start_detection(self):
        """Start real-time detection"""
        if self.running:
            self.logger.warning("Detection already running")
            return
        
        self.running = True
        self.start_time = time.time()
        
        self.detection_thread = threading.Thread(target=self._detection_loop)
        self.detection_thread.daemon = True
        self.detection_thread.start()
        
        self.logger.info("Real-time detection started")
    
    def stop_detection(self):
        """Stop real-time detection"""
        self.running = False
        if self.detection_thread:
            self.detection_thread.join(timeout=5)
        self.logger.info("Real-time detection stopped")
    
    def process_packet(self, packet_data):
        """
        Process a single packet for real-time detection
        
        Args:
            packet_data: Packet information dictionary
        """
        try:
            self.packet_buffer.append(packet_data)
            self.packets_processed += 1
            
            # Check if we should run detection (buffer is full or special packet)
            if len(self.packet_buffer) >= self.window_size or self._is_special_packet(packet_data):
                self._run_detection()
                
        except Exception as e:
            self.logger.error(f"Error processing packet: {str(e)}")
    
    def _detection_loop(self):
        """Main detection loop"""
        while self.running:
            try:
                if len(self.packet_buffer) >= self.window_size // 2:
                    self._run_detection()
                
                time.sleep(self.detection_interval)
                
            except Exception as e:
                self.logger.error(f"Error in detection loop: {str(e)}")
                time.sleep(1)  # Brief pause on error
    
    def _run_detection(self):
        """Run anomaly detection on current buffer"""
        try:
            if len(self.packet_buffer) < 10:  # Minimum packets for detection
                return
            
            # Convert packet buffer to features (this would use feature extractor)
            # For now, we'll simulate this step
            features_df = self._packets_to_features(list(self.packet_buffer))
            
            if features_df.empty:
                return
            
            # Run anomaly detection
            results = self.anomaly_detector.predict(features_df)
            
            # Process anomalies
            anomaly_indices = np.where(results['predictions'] == 1)[0]
            
            for idx in anomaly_indices:
                if idx < len(self.packet_buffer):
                    packet_data = self.packet_buffer[idx]
                    confidence = results['scores'][idx] if idx < len(results['scores']) else 0.5
                    
                    # Create alert
                    self.alert_manager.create_alert(
                        anomaly_data=results,
                        packet_info=packet_data,
                        confidence=confidence
                    )
                    
                    self.anomalies_detected += 1
            
            # Clear buffer after detection
            self.packet_buffer.clear()
            
            self.logger.info(f"Detection completed: {len(anomaly_indices)} anomalies found")
            
        except Exception as e:
            self.logger.error(f"Error running detection: {str(e)}")
    
    def _packets_to_features(self, packets):
        """Convert packets to features (placeholder)"""
        # This would use the actual feature extractor
        # For now, return empty DataFrame
        import pandas as pd
        return pd.DataFrame()
    
    def _is_special_packet(self, packet_data):
        """Check if packet requires immediate attention"""
        # Check for suspicious ports, protocols, etc.
        suspicious_ports = [22, 23, 3389, 445, 139]
        
        src_port = packet_data.get('src_port', 0)
        dst_port = packet_data.get('dst_port', 0)
        
        return src_port in suspicious_ports or dst_port in suspicious_ports
    
    def get_statistics(self):
        """Get detection statistics"""
        uptime = time.time() - self.start_time if self.start_time else 0
        
        return {
            'packets_processed': self.packets_processed,
            'anomalies_detected': self.anomalies_detected,
            'detection_rate': self.anomalies_detected / max(self.packets_processed, 1),
            'uptime_seconds': uptime,
            'buffer_size': len(self.packet_buffer),
            'is_running': self.running
        }


# Import required modules at the top
import os
import numpy as np