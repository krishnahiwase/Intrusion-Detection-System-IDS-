#!/usr/bin/env python3
"""
Network Intrusion Detection System (IDS)
Main application entry point
"""

import argparse
import sys
import os
from datetime import datetime

# Add src directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from config import setup_logging, NETWORK_INTERFACE, CAPTURE_DURATION
from src.packet_capture import PacketCapture
from src.feature_extractor import FeatureExtractor
from src.ml_detector import MLDetector
from src.rule_detector import RuleDetector
from src.alert_system import AlertSystem
from src.data_exporter import DataExporter
from src.visualization import TrafficVisualizer

class IDS:
    """Main IDS application class"""
    
    def __init__(self, mode='ml', interface=None, duration=None, output_file=None):
        """
        Initialize the IDS system
        
        Args:
            mode: Detection mode ('ml', 'rule', or 'hybrid')
            interface: Network interface to monitor
            duration: Capture duration in seconds
            output_file: Output file for results
        """
        self.mode = mode
        self.interface = interface or NETWORK_INTERFACE
        self.duration = duration or CAPTURE_DURATION
        self.output_file = output_file
        
        # Initialize logger
        self.logger = setup_logging()
        self.logger.info(f"Initializing IDS in {mode} mode")
        
        # Initialize components
        self.packet_capture = PacketCapture(self.interface)
        self.feature_extractor = FeatureExtractor()
        self.alert_system = AlertSystem()
        self.data_exporter = DataExporter()
        self.visualizer = TrafficVisualizer()
        
        # Initialize detectors based on mode
        if mode in ['ml', 'hybrid']:
            self.ml_detector = MLDetector()
        if mode in ['rule', 'hybrid']:
            self.rule_detector = RuleDetector()
            
        self.logger.info("IDS initialization complete")
    
    def run_ml_detection(self, packets):
        """Run machine learning-based detection"""
        self.logger.info("Running ML-based anomaly detection")
        
        # Extract features from packets
        features = self.feature_extractor.extract_features(packets)
        
        # Run ML detection
        anomalies = self.ml_detector.detect_anomalies(features)
        
        # Generate alerts for anomalies
        for i, is_anomaly in enumerate(anomalies):
            if is_anomaly:
                packet_info = packets[i] if i < len(packets) else {}
                self.alert_system.generate_alert(
                    'ml_anomaly', 
                    packet_info, 
                    severity='high',
                    details=f"ML model detected anomaly in packet {i}"
                )
        
        return anomalies, features
    
    def run_rule_detection(self, packets):
        """Run rule-based detection"""
        self.logger.info("Running rule-based detection")
        
        violations = []
        
        for i, packet in enumerate(packets):
            # Check packet against rules
            rule_violations = self.rule_detector.check_packet(packet)
            
            if rule_violations:
                violations.append({
                    'packet_index': i,
                    'violations': rule_violations,
                    'packet_info': packet
                })
                
                # Generate alerts for rule violations
                for violation in rule_violations:
                    self.alert_system.generate_alert(
                        'rule_violation',
                        packet,
                        severity=violation.get('severity', 'medium'),
                        details=violation.get('description', 'Rule violation detected')
                    )
        
        return violations
    
    def run_detection(self, packets):
        """Run detection based on selected mode"""
        self.logger.info(f"Running detection in {self.mode} mode")
        
        results = {}
        
        if self.mode == 'ml':
            anomalies, features = self.run_ml_detection(packets)
            results['ml_results'] = {
                'anomalies': anomalies,
                'features': features,
                'anomaly_count': sum(anomalies)
            }
            
        elif self.mode == 'rule':
            violations = self.run_rule_detection(packets)
            results['rule_results'] = {
                'violations': violations,
                'violation_count': len(violations)
            }
            
        elif self.mode == 'hybrid':
            # Run both ML and rule-based detection
            anomalies, features = self.run_ml_detection(packets)
            violations = self.run_rule_detection(packets)
            
            results['hybrid_results'] = {
                'ml_anomalies': {
                    'anomalies': anomalies,
                    'features': features,
                    'anomaly_count': sum(anomalies)
                },
                'rule_violations': {
                    'violations': violations,
                    'violation_count': len(violations)
                }
            }
        
        return results
    
    def run(self):
        """Main execution method"""
        self.logger.info("Starting IDS execution")
        
        try:
            # Start packet capture
            self.logger.info(f"Starting packet capture on {self.interface} for {self.duration} seconds")
            packets = self.packet_capture.capture_packets(duration=self.duration)
            
            if not packets:
                self.logger.warning("No packets captured")
                return
            
            self.logger.info(f"Captured {len(packets)} packets")
            
            # Run detection
            detection_results = self.run_detection(packets)
            
            # Generate summary report
            self.generate_report(packets, detection_results)
            
            # Export data if requested
            if self.output_file:
                self.data_exporter.export_to_csv(packets, detection_results, self.output_file)
                self.logger.info(f"Results exported to {self.output_file}")
            
            # Create visualizations
            self.create_visualizations(packets, detection_results)
            
            self.logger.info("IDS execution completed successfully")
            
        except KeyboardInterrupt:
            self.logger.info("IDS execution interrupted by user")
        except Exception as e:
            self.logger.error(f"Error during IDS execution: {str(e)}")
            raise
    
    def generate_report(self, packets, detection_results):
        """Generate detection summary report"""
        self.logger.info("Generating detection report")
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_packets': len(packets),
            'detection_mode': self.mode,
            'interface': self.interface,
            'duration': self.duration
        }
        
        if self.mode == 'ml' and 'ml_results' in detection_results:
            ml_results = detection_results['ml_results']
            report['ml_summary'] = {
                'anomalies_detected': ml_results['anomaly_count'],
                'anomaly_percentage': (ml_results['anomaly_count'] / len(packets)) * 100
            }
        
        elif self.mode == 'rule' and 'rule_results' in detection_results:
            rule_results = detection_results['rule_results']
            report['rule_summary'] = {
                'violations_detected': rule_results['violation_count']
            }
        
        elif self.mode == 'hybrid' and 'hybrid_results' in detection_results:
            hybrid_results = detection_results['hybrid_results']
            report['hybrid_summary'] = {
                'ml_anomalies': hybrid_results['ml_anomalies']['anomaly_count'],
                'rule_violations': hybrid_results['rule_violations']['violation_count']
            }
        
        self.logger.info(f"Detection Report: {report}")
        return report
    
    def create_visualizations(self, packets, detection_results):
        """Create traffic visualizations"""
        self.logger.info("Creating visualizations")
        
        try:
            # Create traffic overview
            self.visualizer.plot_traffic_overview(packets)
            
            # Create detection results visualization
            if self.mode == 'ml':
                self.visualizer.plot_ml_results(detection_results.get('ml_results', {}))
            elif self.mode == 'rule':
                self.visualizer.plot_rule_results(detection_results.get('rule_results', {}))
            elif self.mode == 'hybrid':
                self.visualizer.plot_hybrid_results(detection_results.get('hybrid_results', {}))
            
            self.logger.info("Visualizations created successfully")
            
        except Exception as e:
            self.logger.error(f"Error creating visualizations: {str(e)}")

def main():
    """Main function with argument parsing"""
    parser = argparse.ArgumentParser(description='Network Intrusion Detection System')
    parser.add_argument('--mode', choices=['ml', 'rule', 'hybrid'], default='ml',
                        help='Detection mode (default: ml)')
    parser.add_argument('--interface', type=str, default=None,
                        help='Network interface to monitor')
    parser.add_argument('--duration', type=int, default=None,
                        help='Capture duration in seconds')
    parser.add_argument('--output', type=str, default=None,
                        help='Output file for results (CSV format)')
    parser.add_argument('--train', action='store_true',
                        help='Train ML models on captured data')
    parser.add_argument('--web', action='store_true',
                        help='Start web dashboard')
    
    args = parser.parse_args()
    
    # Start web dashboard if requested
    if args.web:
        print("Starting web dashboard...")
        os.system('cd web_dashboard && python app.py')
        return
    
    # Initialize and run IDS
    ids = IDS(
        mode=args.mode,
        interface=args.interface,
        duration=args.duration,
        output_file=args.output
    )
    
    try:
        ids.run()
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()