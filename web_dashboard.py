"""
Web Dashboard for Network IDS
Flask-based web interface for real-time monitoring and visualization
"""

from flask import Flask, render_template, jsonify, request, Response
import json
import logging
import threading
import time
from datetime import datetime
import os
import sys
from typing import Dict, List, Optional
import pandas as pd

# Add src directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from src.packet_capture import PacketCapture
from src.feature_extractor import FeatureExtractor
from src.anomaly_detector import AnomalyDetector
from src.rule_detector import RuleBasedDetector
from src.alert_system import AlertManager, RealtimeDetector
from src.visualizer import TrafficVisualizer
from src.config import *

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ids-dashboard-secret-key'

# Global variables for dashboard state
dashboard_state = {
    'running': False,
    'mode': 'ml',
    'interface': None,
    'stats': {
        'total_packets': 0,
        'anomalies_detected': 0,
        'alerts_generated': 0,
        'detection_rate': 0.0
    },
    'alerts': [],
    'packets': [],
    'charts': {}
}

# Initialize components
packet_capture = None
feature_extractor = None
anomaly_detector = None
rule_detector = None
alert_manager = None
visualizer = None
realtime_detector = None

# Thread for real-time detection
detection_thread = None

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def initialize_components(mode='ml'):
    """Initialize IDS components"""
    global packet_capture, feature_extractor, anomaly_detector, rule_detector, alert_manager, visualizer, realtime_detector
    
    try:
        logger.info(f"Initializing components in {mode} mode...")
        
        packet_capture = PacketCapture()
        feature_extractor = FeatureExtractor()
        alert_manager = AlertManager()
        visualizer = TrafficVisualizer()
        
        if mode == 'ml' or mode == 'hybrid':
            anomaly_detector = AnomalyDetector()
            
        if mode == 'rule' or mode == 'hybrid':
            rule_detector = RuleBasedDetector()
        
        realtime_detector = RealtimeDetector(
            feature_extractor=feature_extractor,
            anomaly_detector=anomaly_detector,
            rule_detector=rule_detector,
            alert_manager=alert_manager,
            mode=mode
        )
        
        logger.info("Components initialized successfully")
        return True
        
    except Exception as e:
        logger.error(f"Error initializing components: {str(e)}")
        return False

def realtime_detection_loop():
    """Real-time detection loop for dashboard"""
    global dashboard_state
    
    while dashboard_state['running']:
        try:
            # Capture packets
            packets = packet_capture.capture_live(
                interface=dashboard_state['interface'],
                count=50,
                timeout=10
            )
            
            if packets:
                # Update packet statistics
                dashboard_state['stats']['total_packets'] += len(packets)
                
                # Extract features
                features = []
                for packet in packets:
                    feature_vector = feature_extractor.extract_features(packet)
                    if feature_vector:
                        features.append(feature_vector)
                
                if features:
                    # Detect anomalies
                    if dashboard_state['mode'] in ['ml', 'hybrid']:
                        features_df = pd.DataFrame(features)
                        anomaly_results = anomaly_detector.predict(features_df)
                        
                        # Update anomaly statistics
                        anomaly_count = sum(anomaly_results['predictions'])
                        dashboard_state['stats']['anomalies_detected'] += anomaly_count
                    
                    # Apply rule detection
                    if dashboard_state['mode'] in ['rule', 'hybrid']:
                        alerts = []
                        for packet in packets:
                            packet_alerts = rule_detector.analyze_packet(packet)
                            alerts.extend(packet_alerts)
                        
                        # Update alert statistics
                        dashboard_state['stats']['alerts_generated'] += len(alerts)
                        
                        # Add alerts to dashboard
                        for alert in alerts:
                            alert_data = {
                                'timestamp': datetime.now().isoformat(),
                                'type': alert.get('rule_category', 'unknown'),
                                'severity': alert.get('severity', 'medium'),
                                'description': alert.get('description', 'Unknown alert'),
                                'source_ip': alert.get('source_ip', 'unknown'),
                                'destination_ip': alert.get('destination_ip', 'unknown')
                            }
                            dashboard_state['alerts'].append(alert_data)
                            
                            # Keep only recent alerts (last 100)
                            if len(dashboard_state['alerts']) > 100:
                                dashboard_state['alerts'] = dashboard_state['alerts'][-100:]
                
                # Update detection rate
                if dashboard_state['stats']['total_packets'] > 0:
                    dashboard_state['stats']['detection_rate'] = (
                        dashboard_state['stats']['anomalies_detected'] / 
                        dashboard_state['stats']['total_packets'] * 100
                    )
                
                # Generate charts
                generate_dashboard_charts()
            
            # Wait before next capture
            time.sleep(5)
            
        except Exception as e:
            logger.error(f"Error in detection loop: {str(e)}")
            time.sleep(5)

def generate_dashboard_charts():
    """Generate dashboard charts"""
    try:
        # Create sample data for charts
        import numpy as np
        
        # Traffic over time chart
        time_data = pd.date_range(start='now', periods=20, freq='1T')
        traffic_data = np.random.randint(10, 100, size=20)
        
        traffic_fig = visualizer.create_real_time_chart(
            pd.Series(traffic_data, index=time_data),
            chart_type='line'
        )
        
        if traffic_fig:
            dashboard_state['charts']['traffic_over_time'] = visualizer.save_figure_as_base64(traffic_fig)
        
        # Protocol distribution
        protocols = ['TCP', 'UDP', 'ICMP', 'Other']
        protocol_counts = np.random.randint(10, 50, size=4)
        
        protocol_fig = visualizer.create_real_time_chart(
            dict(zip(protocols, protocol_counts)),
            chart_type='pie'
        )
        
        if protocol_fig:
            dashboard_state['charts']['protocol_distribution'] = visualizer.save_figure_as_base64(protocol_fig)
        
        # Alert severity distribution
        severities = ['Low', 'Medium', 'High']
        severity_counts = [len([a for a in dashboard_state['alerts'] if a['severity'].lower() == sev.lower()]) 
                          for sev in severities]
        
        severity_fig = visualizer.create_real_time_chart(
            dict(zip(severities, severity_counts)),
            chart_type='bar'
        )
        
        if severity_fig:
            dashboard_state['charts']['alert_severity'] = visualizer.save_figure_as_base64(severity_fig)
        
    except Exception as e:
        logger.error(f"Error generating charts: {str(e)}")

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html', 
                         title='Network IDS Dashboard',
                         stats=dashboard_state['stats'],
                         alerts=dashboard_state['alerts'][-10:],  # Last 10 alerts
                         charts=dashboard_state['charts'])

@app.route('/api/status')
def api_status():
    """API endpoint for system status"""
    return jsonify({
        'running': dashboard_state['running'],
        'mode': dashboard_state['mode'],
        'interface': dashboard_state['interface'],
        'stats': dashboard_state['stats'],
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/alerts')
def api_alerts():
    """API endpoint for alerts"""
    limit = request.args.get('limit', 50, type=int)
    return jsonify(dashboard_state['alerts'][-limit:])

@app.route('/api/start', methods=['POST'])
def start_detection():
    """Start real-time detection"""
    global detection_thread, dashboard_state
    
    try:
        data = request.get_json()
        mode = data.get('mode', 'ml')
        interface = data.get('interface', None)
        
        if dashboard_state['running']:
            return jsonify({'error': 'Detection already running'}), 400
        
        # Initialize components
        if not initialize_components(mode):
            return jsonify({'error': 'Failed to initialize components'}), 500
        
        # Update dashboard state
        dashboard_state['running'] = True
        dashboard_state['mode'] = mode
        dashboard_state['interface'] = interface
        
        # Start detection thread
        detection_thread = threading.Thread(target=realtime_detection_loop)
        detection_thread.daemon = True
        detection_thread.start()
        
        logger.info(f"Detection started in {mode} mode")
        return jsonify({'message': 'Detection started successfully'})
        
    except Exception as e:
        logger.error(f"Error starting detection: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/stop', methods=['POST'])
def stop_detection():
    """Stop real-time detection"""
    global dashboard_state
    
    try:
        if not dashboard_state['running']:
            return jsonify({'error': 'Detection not running'}), 400
        
        dashboard_state['running'] = False
        
        if detection_thread and detection_thread.is_alive():
            detection_thread.join(timeout=5)
        
        logger.info("Detection stopped")
        return jsonify({'message': 'Detection stopped successfully'})
        
    except Exception as e:
        logger.error(f"Error stopping detection: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats')
def api_stats():
    """API endpoint for statistics"""
    return jsonify(dashboard_state['stats'])

@app.route('/api/charts')
def api_charts():
    """API endpoint for charts"""
    return jsonify(dashboard_state['charts'])

@app.route('/api/export', methods=['POST'])
def export_data():
    """Export data to CSV"""
    try:
        data_type = request.json.get('type', 'alerts')
        
        if data_type == 'alerts':
            df = pd.DataFrame(dashboard_state['alerts'])
            csv_data = df.to_csv(index=False)
        elif data_type == 'stats':
            df = pd.DataFrame([dashboard_state['stats']])
            csv_data = df.to_csv(index=False)
        else:
            return jsonify({'error': 'Invalid export type'}), 400
        
        response = Response(
            csv_data,
            mimetype='text/csv',
            headers={
                'Content-Disposition': f'attachment; filename=ids_{data_type}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
            }
        )
        
        return response
        
    except Exception as e:
        logger.error(f"Error exporting data: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/settings')
def settings():
    """Settings page"""
    return render_template('settings.html',
                         title='IDS Settings',
                         available_interfaces=['eth0', 'wlan0', 'any'],
                         detection_modes=['ml', 'rule', 'hybrid'])

@app.route('/logs')
def logs():
    """Logs page"""
    return render_template('logs.html', title='System Logs')

@app.route('/api/logs')
def api_logs():
    """API endpoint for logs"""
    try:
        # Read log file
        log_file = 'ids_cli.log'
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                logs = f.readlines()[-100:]  # Last 100 lines
            return jsonify({'logs': logs})
        else:
            return jsonify({'logs': ['No log file found']})
    except Exception as e:
        logger.error(f"Error reading logs: {str(e)}")
        return jsonify({'logs': [f'Error reading logs: {str(e)}']})

# Create templates directory and HTML templates
templates_dir = os.path.join(os.path.dirname(__file__), 'templates')
os.makedirs(templates_dir, exist_ok=True)

# Dashboard HTML template
dashboard_template = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        .metric-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 15px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }
        .alert-card {
            background: #f8f9fa;
            border-left: 4px solid #dc3545;
            margin-bottom: 10px;
            padding: 15px;
            border-radius: 5px;
        }
        .chart-container {
            background: white;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .status-indicator {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            display: inline-block;
            margin-right: 5px;
        }
        .status-running { background-color: #28a745; }
        .status-stopped { background-color: #dc3545; }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="#">Network IDS Dashboard</a>
            <div class="navbar-nav ms-auto">
                <span class="status-indicator status-{{ 'running' if dashboard_state.running else 'stopped' }}"></span>
                <span class="text-light">{{ 'Running' if dashboard_state.running else 'Stopped' }}</span>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <!-- Control Panel -->
        <div class="row mb-4">
            <div class="col-md-12">
                <div class="card">
                    <div class="card-header">
                        <h5>Control Panel</h5>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-3">
                                <select class="form-select" id="detectionMode">
                                    <option value="ml">ML Detection</option>
                                    <option value="rule">Rule Detection</option>
                                    <option value="hybrid">Hybrid Detection</option>
                                </select>
                            </div>
                            <div class="col-md-3">
                                <select class="form-select" id="interface">
                                    <option value="">Any Interface</option>
                                    <option value="eth0">eth0</option>
                                    <option value="wlan0">wlan0</option>
                                </select>
                            </div>
                            <div class="col-md-6">
                                <button class="btn btn-success" id="startBtn" onclick="startDetection()">Start Detection</button>
                                <button class="btn btn-danger" id="stopBtn" onclick="stopDetection()" disabled>Stop Detection</button>
                                <button class="btn btn-primary" onclick="refreshDashboard()">Refresh</button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Metrics -->
        <div class="row">
            <div class="col-md-3">
                <div class="metric-card">
                    <h4>Total Packets</h4>
                    <h2 id="totalPackets">{{ stats.total_packets }}</h2>
                </div>
            </div>
            <div class="col-md-3">
                <div class="metric-card" style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);">
                    <h4>Anomalies Detected</h4>
                    <h2 id="anomaliesDetected">{{ stats.anomalies_detected }}</h2>
                </div>
            </div>
            <div class="col-md-3">
                <div class="metric-card" style="background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);">
                    <h4>Alerts Generated</h4>
                    <h2 id="alertsGenerated">{{ stats.alerts_generated }}</h2>
                </div>
            </div>
            <div class="col-md-3">
                <div class="metric-card" style="background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%);">
                    <h4>Detection Rate</h4>
                    <h2 id="detectionRate">{{ "%.2f"|format(stats.detection_rate) }}%</h2>
                </div>
            </div>
        </div>

        <!-- Charts -->
        <div class="row mt-4">
            <div class="col-md-6">
                <div class="chart-container">
                    <h5>Traffic Over Time</h5>
                    <img src="data:image/png;base64,{{ charts.traffic_over_time }}" alt="Traffic Over Time" class="img-fluid">
                </div>
            </div>
            <div class="col-md-6">
                <div class="chart-container">
                    <h5>Protocol Distribution</h5>
                    <img src="data:image/png;base64,{{ charts.protocol_distribution }}" alt="Protocol Distribution" class="img-fluid">
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-md-6">
                <div class="chart-container">
                    <h5>Alert Severity</h5>
                    <img src="data:image/png;base64,{{ charts.alert_severity }}" alt="Alert Severity" class="img-fluid">
                </div>
            </div>
            <div class="col-md-6">
                <div class="chart-container">
                    <h5>Recent Activity</h5>
                    <div style="height: 300px; overflow-y: auto;">
                        <table class="table table-sm">
                            <thead>
                                <tr>
                                    <th>Time</th>
                                    <th>Type</th>
                                    <th>Source</th>
                                    <th>Severity</th>
                                </tr>
                            </thead>
                            <tbody id="recentActivity">
                                {% for alert in alerts %}
                                <tr>
                                    <td>{{ alert.timestamp[:19] }}</td>
                                    <td>{{ alert.type }}</td>
                                    <td>{{ alert.source_ip }}</td>
                                    <td>
                                        <span class="badge bg-{% if alert.severity == 'high' %}danger{% elif alert.severity == 'medium' %}warning{% else %}success{% endif %}">
                                            {{ alert.severity }}
                                        </span>
                                    </td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <!-- Recent Alerts -->
        <div class="row mt-4">
            <div class="col-md-12">
                <div class="card">
                    <div class="card-header">
                        <h5>Recent Alerts</h5>
                    </div>
                    <div class="card-body">
                        <div id="alertsContainer">
                            {% for alert in alerts %}
                            <div class="alert-card">
                                <div class="row">
                                    <div class="col-md-2">
                                        <strong>{{ alert.timestamp[:19] }}</strong>
                                    </div>
                                    <div class="col-md-2">
                                        <span class="badge bg-{% if alert.severity == 'high' %}danger{% elif alert.severity == 'medium' %}warning{% else %}success{% endif %}">
                                            {{ alert.severity|upper }}
                                        </span>
                                    </div>
                                    <div class="col-md-2">
                                        {{ alert.type }}
                                    </div>
                                    <div class="col-md-3">
                                        <strong>Source:</strong> {{ alert.source_ip }}<br>
                                        <strong>Destination:</strong> {{ alert.destination_ip }}
                                    </div>
                                    <div class="col-md-3">
                                        {{ alert.description }}
                                    </div>
                                </div>
                            </div>
                            {% endfor %}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        function startDetection() {
            const mode = document.getElementById('detectionMode').value;
            const interface = document.getElementById('interface').value;
            
            fetch('/api/start', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ mode: mode, interface: interface })
            })
            .then(response => response.json())
            .then(data => {
                if (data.message) {
                    document.getElementById('startBtn').disabled = true;
                    document.getElementById('stopBtn').disabled = false;
                    alert('Detection started successfully');
                } else {
                    alert('Error: ' + data.error);
                }
            });
        }
        
        function stopDetection() {
            fetch('/api/stop', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.message) {
                    document.getElementById('startBtn').disabled = false;
                    document.getElementById('stopBtn').disabled = true;
                    alert('Detection stopped successfully');
                } else {
                    alert('Error: ' + data.error);
                }
            });
        }
        
        function refreshDashboard() {
            location.reload();
        }
        
        // Auto-refresh every 30 seconds
        setInterval(function() {
            if (!document.getElementById('startBtn').disabled) {
                refreshDashboard();
            }
        }, 30000);
    </script>
</body>
</html>'''

# Settings template
settings_template = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="/">Network IDS Dashboard</a>
            <div class="navbar-nav ms-auto">
                <a class="nav-link" href="/">Dashboard</a>
                <a class="nav-link active" href="/settings">Settings</a>
                <a class="nav-link" href="/logs">Logs</a>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <div class="row">
            <div class="col-md-8 offset-md-2">
                <div class="card">
                    <div class="card-header">
                        <h5>IDS Configuration Settings</h5>
                    </div>
                    <div class="card-body">
                        <form id="settingsForm">
                            <div class="mb-3">
                                <label for="defaultInterface" class="form-label">Default Network Interface</label>
                                <select class="form-select" id="defaultInterface">
                                    {% for interface in available_interfaces %}
                                    <option value="{{ interface }}">{{ interface }}</option>
                                    {% endfor %}
                                </select>
                            </div>
                            
                            <div class="mb-3">
                                <label for="defaultMode" class="form-label">Default Detection Mode</label>
                                <select class="form-select" id="defaultMode">
                                    {% for mode in detection_modes %}
                                    <option value="{{ mode }}">{{ mode|upper }}</option>
                                    {% endfor %}
                                </select>
                            </div>
                            
                            <div class="mb-3">
                                <label for="alertThreshold" class="form-label">Alert Threshold</label>
                                <input type="range" class="form-range" min="0" max="100" id="alertThreshold">
                                <div class="form-text">Adjust sensitivity of anomaly detection</div>
                            </div>
                            
                            <button type="submit" class="btn btn-primary">Save Settings</button>
                            <button type="button" class="btn btn-secondary" onclick="window.location.href='/'">Cancel</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        document.getElementById('settingsForm').addEventListener('submit', function(e) {
            e.preventDefault();
            alert('Settings saved successfully!');
            window.location.href = '/';
        });
    </script>
</body>
</html>'''

# Logs template
logs_template = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="/">Network IDS Dashboard</a>
            <div class="navbar-nav ms-auto">
                <a class="nav-link" href="/">Dashboard</a>
                <a class="nav-link" href="/settings">Settings</a>
                <a class="nav-link active" href="/logs">Logs</a>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <div class="row">
            <div class="col-md-12">
                <div class="card">
                    <div class="card-header">
                        <h5>System Logs</h5>
                    </div>
                    <div class="card-body">
                        <div id="logsContainer" style="height: 500px; overflow-y: auto; background-color: #f8f9fa; padding: 10px; font-family: monospace; font-size: 12px;">
                            Loading logs...
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        function loadLogs() {
            fetch('/api/logs')
                .then(response => response.json())
                .then(data => {
                    const logsContainer = document.getElementById('logsContainer');
                    logsContainer.innerHTML = data.logs.join('<br>');
                    logsContainer.scrollTop = logsContainer.scrollHeight;
                });
        }
        
        // Load logs initially
        loadLogs();
        
        // Refresh logs every 10 seconds
        setInterval(loadLogs, 10000);
    </script>
</body>
</html>'''

# Write templates to files
def create_templates():
    """Create HTML template files"""
    try:
        with open(os.path.join(templates_dir, 'dashboard.html'), 'w') as f:
            f.write(dashboard_template)
        
        with open(os.path.join(templates_dir, 'settings.html'), 'w') as f:
            f.write(settings_template)
        
        with open(os.path.join(templates_dir, 'logs.html'), 'w') as f:
            f.write(logs_template)
        
        logger.info("Templates created successfully")
        return True
        
    except Exception as e:
        logger.error(f"Error creating templates: {str(e)}")
        return False

if __name__ == '__main__':
    # Create templates
    if create_templates():
        logger.info("Starting Flask web dashboard...")
        
        try:
            app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)
        except KeyboardInterrupt:
            logger.info("Shutting down web dashboard...")
        except Exception as e:
            logger.error(f"Error running web dashboard: {str(e)}")
    else:
        logger.error("Failed to create templates. Exiting...")