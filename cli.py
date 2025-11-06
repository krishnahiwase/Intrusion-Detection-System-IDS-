"""
Command Line Interface for Network IDS
Provides interactive command-line interface for the Network Intrusion Detection System
"""

import argparse
import logging
import sys
import os
import time
from datetime import datetime
import json
import threading
from typing import Optional, Dict, Any

# Add src directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from src.packet_capture import PacketCapture
from src.feature_extractor import FeatureExtractor
from src.anomaly_detector import AnomalyDetector
from src.rule_detector import RuleBasedDetector
from src.alert_system import AlertManager, RealtimeDetector
from src.visualizer import TrafficVisualizer
from src.config import *

class IDSCLI:
    """Command Line Interface for Network IDS"""
    
    def __init__(self):
        self.logger = self._setup_logging()
        self.packet_capture = None
        self.feature_extractor = None
        self.anomaly_detector = None
        self.rule_detector = None
        self.alert_manager = None
        self.visualizer = None
        self.realtime_detector = None
        self.running = False
        self.detection_thread = None
        
    def _setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('ids_cli.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        return logging.getLogger(__name__)
    
    def initialize_components(self, mode='ml'):
        """Initialize IDS components"""
        try:
            self.logger.info(f"Initializing IDS components in {mode} mode...")
            
            # Initialize components
            self.packet_capture = PacketCapture()
            self.feature_extractor = FeatureExtractor()
            self.alert_manager = AlertManager()
            self.visualizer = TrafficVisualizer()
            
            if mode == 'ml' or mode == 'hybrid':
                self.anomaly_detector = AnomalyDetector()
                
            if mode == 'rule' or mode == 'hybrid':
                self.rule_detector = RuleBasedDetector()
            
            # Initialize real-time detector
            self.realtime_detector = RealtimeDetector(
                feature_extractor=self.feature_extractor,
                anomaly_detector=self.anomaly_detector,
                rule_detector=self.rule_detector,
                alert_manager=self.alert_manager,
                mode=mode
            )
            
            self.logger.info("IDS components initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error initializing components: {str(e)}")
            return False
    
    def capture_packets(self, interface=None, count=100, timeout=30):
        """Capture network packets"""
        try:
            self.logger.info(f"Starting packet capture (interface: {interface}, count: {count})")
            
            if interface:
                packets = self.packet_capture.capture_live(interface, count, timeout)
            else:
                packets = self.packet_capture.capture_from_pcap('sample_traffic.pcap')
            
            self.logger.info(f"Captured {len(packets)} packets")
            return packets
            
        except Exception as e:
            self.logger.error(f"Error capturing packets: {str(e)}")
            return []
    
    def extract_features(self, packets):
        """Extract features from packets"""
        try:
            self.logger.info("Extracting features from packets...")
            
            features = []
            for packet in packets:
                feature_vector = self.feature_extractor.extract_features(packet)
                if feature_vector:
                    features.append(feature_vector)
            
            self.logger.info(f"Extracted features from {len(features)} packets")
            return features
            
        except Exception as e:
            self.logger.error(f"Error extracting features: {str(e)}")
            return []
    
    def train_model(self, features):
        """Train anomaly detection model"""
        try:
            self.logger.info("Training anomaly detection model...")
            
            if not self.anomaly_detector:
                self.logger.error("Anomaly detector not initialized")
                return False
            
            # Convert features to DataFrame
            import pandas as pd
            features_df = pd.DataFrame(features)
            
            # Train the model
            self.anomaly_detector.train(features_df)
            
            self.logger.info("Model training completed")
            return True
            
        except Exception as e:
            self.logger.error(f"Error training model: {str(e)}")
            return False
    
    def detect_anomalies(self, features):
        """Detect anomalies in features"""
        try:
            self.logger.info("Detecting anomalies...")
            
            if not self.anomaly_detector:
                self.logger.error("Anomaly detector not initialized")
                return []
            
            # Convert features to DataFrame
            import pandas as pd
            features_df = pd.DataFrame(features)
            
            # Detect anomalies
            results = self.anomaly_detector.predict(features_df)
            
            self.logger.info(f"Detected {sum(results['predictions'])} anomalies out of {len(features)} samples")
            return results
            
        except Exception as e:
            self.logger.error(f"Error detecting anomalies: {str(e)}")
            return []
    
    def apply_rule_detection(self, packets):
        """Apply rule-based detection"""
        try:
            self.logger.info("Applying rule-based detection...")
            
            if not self.rule_detector:
                self.logger.error("Rule detector not initialized")
                return []
            
            alerts = []
            for packet in packets:
                packet_alerts = self.rule_detector.analyze_packet(packet)
                alerts.extend(packet_alerts)
            
            self.logger.info(f"Generated {len(alerts)} rule-based alerts")
            return alerts
            
        except Exception as e:
            self.logger.error(f"Error in rule detection: {str(e)}")
            return []
    
    def start_realtime_detection(self, interface=None, mode='ml'):
        """Start real-time detection"""
        try:
            self.logger.info(f"Starting real-time detection in {mode} mode...")
            
            if not self.initialize_components(mode):
                return False
            
            self.running = True
            
            # Start detection thread
            self.detection_thread = threading.Thread(
                target=self._realtime_detection_loop,
                args=(interface, mode)
            )
            self.detection_thread.daemon = True
            self.detection_thread.start()
            
            self.logger.info("Real-time detection started")
            return True
            
        except Exception as e:
            self.logger.error(f"Error starting real-time detection: {str(e)}")
            return False
    
    def _realtime_detection_loop(self, interface=None, mode='ml'):
        """Real-time detection loop"""
        try:
            while self.running:
                # Capture packets
                packets = self.capture_packets(interface, count=50, timeout=10)
                
                if packets:
                    # Extract features
                    features = self.extract_features(packets)
                    
                    if features and mode in ['ml', 'hybrid']:
                        # Detect anomalies
                        anomalies = self.detect_anomalies(features)
                        
                    if mode in ['rule', 'hybrid']:
                        # Apply rule detection
                        rule_alerts = self.apply_rule_detection(packets)
                    
                    # Wait before next capture
                    time.sleep(5)
                else:
                    time.sleep(2)
                    
        except Exception as e:
            self.logger.error(f"Error in real-time detection loop: {str(e)}")
    
    def stop_realtime_detection(self):
        """Stop real-time detection"""
        try:
            self.logger.info("Stopping real-time detection...")
            self.running = False
            
            if self.detection_thread and self.detection_thread.is_alive():
                self.detection_thread.join(timeout=5)
            
            self.logger.info("Real-time detection stopped")
            return True
            
        except Exception as e:
            self.logger.error(f"Error stopping real-time detection: {str(e)}")
            return False
    
    def generate_report(self, output_file='ids_report.json'):
        """Generate comprehensive report"""
        try:
            self.logger.info("Generating comprehensive report...")
            
            report = {
                'timestamp': datetime.now().isoformat(),
                'system_info': {
                    'mode': 'ml' if self.anomaly_detector else 'rule',
                    'total_packets_captured': len(self.packet_capture.packets if self.packet_capture else []),
                    'total_alerts_generated': len(self.alert_manager.alerts if self.alert_manager else [])
                },
                'detection_statistics': self._get_detection_statistics(),
                'top_alerts': self._get_top_alerts(),
                'recommendations': self._generate_recommendations()
            }
            
            # Save report
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            self.logger.info(f"Report saved to {output_file}")
            return report
            
        except Exception as e:
            self.logger.error(f"Error generating report: {str(e)}")
            return None
    
    def _get_detection_statistics(self):
        """Get detection statistics"""
        stats = {
            'total_packets': 0,
            'anomalies_detected': 0,
            'rule_alerts': 0,
            'false_positives': 0,
            'detection_rate': 0.0
        }
        
        # This would be populated with actual statistics
        return stats
    
    def _get_top_alerts(self):
        """Get top alerts"""
        return []
    
    def _generate_recommendations(self):
        """Generate security recommendations"""
        recommendations = [
            "Monitor network traffic during off-hours for unusual activity",
            "Implement rate limiting for suspicious IP addresses",
            "Review firewall rules and access controls",
            "Consider implementing network segmentation",
            "Regularly update intrusion detection signatures"
        ]
        return recommendations
    
    def show_help(self):
        """Show help information"""
        help_text = """
Network Intrusion Detection System - Command Line Interface

Available Commands:
  capture [interface] [count]     - Capture network packets
  train [features_file]          - Train anomaly detection model
  detect [mode] [interface]      - Start detection (ml/rule/hybrid)
  analyze [pcap_file]            - Analyze PCAP file
  visualize [type]               - Generate visualizations
  report [output_file]           - Generate comprehensive report
  status                         - Show system status
  help                           - Show this help message
  quit                           - Exit the application

Examples:
  capture eth0 100               - Capture 100 packets from eth0
  detect ml eth0                 - Start ML-based detection on eth0
  analyze sample.pcap            - Analyze sample PCAP file
  visualize overview             - Generate traffic overview
  report security_report.json    - Generate security report

Detection Modes:
  ml      - Machine Learning based detection
  rule    - Rule-based detection
  hybrid  - Combined ML and rule-based detection

Visualization Types:
  overview   - Traffic overview
  anomaly    - Anomaly analysis
  port       - Port analysis
  security   - Security dashboard
"""
        print(help_text)
    
    def show_status(self):
        """Show system status"""
        status = {
            'System Status': 'Running' if self.running else 'Stopped',
            'Packet Capture': 'Active' if self.packet_capture else 'Inactive',
            'Feature Extractor': 'Active' if self.feature_extractor else 'Inactive',
            'Anomaly Detector': 'Active' if self.anomaly_detector else 'Inactive',
            'Rule Detector': 'Active' if self.rule_detector else 'Inactive',
            'Alert Manager': 'Active' if self.alert_manager else 'Inactive',
            'Visualizer': 'Active' if self.visualizer else 'Inactive'
        }
        
        print("\n=== System Status ===")
        for component, state in status.items():
            print(f"{component:20}: {state}")
        print()
    
    def run_interactive_mode(self):
        """Run interactive command-line mode"""
        print("\n=== Network Intrusion Detection System ===")
        print("Type 'help' for available commands, 'quit' to exit\n")
        
        while True:
            try:
                command = input("ids> ").strip().lower()
                
                if not command:
                    continue
                
                parts = command.split()
                cmd = parts[0]
                args = parts[1:] if len(parts) > 1 else []
                
                if cmd == 'quit' or cmd == 'exit':
                    print("Exiting IDS CLI...")
                    break
                
                elif cmd == 'help':
                    self.show_help()
                
                elif cmd == 'status':
                    self.show_status()
                
                elif cmd == 'capture':
                    interface = args[0] if len(args) > 0 else None
                    count = int(args[1]) if len(args) > 1 else 100
                    packets = self.capture_packets(interface, count)
                    print(f"Captured {len(packets)} packets")
                
                elif cmd == 'train':
                    if len(args) > 0:
                        # Load features from file
                        import pandas as pd
                        features_df = pd.read_csv(args[0])
                        success = self.train_model(features_df.to_dict('records'))
                        print("Model training completed" if success else "Model training failed")
                    else:
                        print("Usage: train [features_file]")
                
                elif cmd == 'detect':
                    if len(args) > 0:
                        mode = args[0]
                        interface = args[1] if len(args) > 1 else None
                        
                        if self.running:
                            print("Detection already running. Stop first with 'stop'")
                        else:
                            success = self.start_realtime_detection(interface, mode)
                            print("Detection started" if success else "Failed to start detection")
                    else:
                        print("Usage: detect [mode] [interface]")
                
                elif cmd == 'stop':
                    success = self.stop_realtime_detection()
                    print("Detection stopped" if success else "Failed to stop detection")
                
                elif cmd == 'analyze':
                    if len(args) > 0:
                        # Analyze PCAP file
                        print(f"Analyzing {args[0]}...")
                        # Implementation for PCAP analysis
                    else:
                        print("Usage: analyze [pcap_file]")
                
                elif cmd == 'visualize':
                    viz_type = args[0] if len(args) > 0 else 'overview'
                    print(f"Generating {viz_type} visualization...")
                    # Implementation for visualization
                
                elif cmd == 'report':
                    output_file = args[0] if len(args) > 0 else 'ids_report.json'
                    report = self.generate_report(output_file)
                    print(f"Report generated: {output_file}")
                
                else:
                    print(f"Unknown command: {cmd}")
                    print("Type 'help' for available commands")
                
            except KeyboardInterrupt:
                print("\nUse 'quit' to exit")
            except Exception as e:
                print(f"Error: {str(e)}")
                self.logger.error(f"Interactive mode error: {str(e)}")

def main():
    """Main CLI function"""
    parser = argparse.ArgumentParser(description='Network Intrusion Detection System CLI')
    parser.add_argument('--mode', choices=['interactive', 'capture', 'train', 'detect', 'analyze'], 
                       default='interactive', help='Operation mode')
    parser.add_argument('--interface', help='Network interface for capture/detection')
    parser.add_argument('--count', type=int, default=100, help='Number of packets to capture')
    parser.add_argument('--input', help='Input file (PCAP or features)')
    parser.add_argument('--output', help='Output file')
    parser.add_argument('--detection-mode', choices=['ml', 'rule', 'hybrid'], 
                       default='ml', help='Detection mode')
    
    args = parser.parse_args()
    
    # Create CLI instance
    cli = IDSCLI()
    
    try:
        if args.mode == 'interactive':
            cli.run_interactive_mode()
        
        elif args.mode == 'capture':
            packets = cli.capture_packets(args.interface, args.count)
            print(f"Captured {len(packets)} packets")
        
        elif args.mode == 'train':
            if args.input:
                import pandas as pd
                features_df = pd.read_csv(args.input)
                success = cli.train_model(features_df.to_dict('records'))
                print("Training completed" if success else "Training failed")
            else:
                print("Training requires --input parameter")
        
        elif args.mode == 'detect':
            cli.start_realtime_detection(args.interface, args.detection_mode)
            try:
                # Keep running until interrupted
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                cli.stop_realtime_detection()
        
        elif args.mode == 'analyze':
            if args.input:
                print(f"Analyzing {args.input}...")
                # Implementation for PCAP analysis
            else:
                print("Analysis requires --input parameter")
    
    except KeyboardInterrupt:
        print("\nShutting down IDS CLI...")
    except Exception as e:
        print(f"Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()