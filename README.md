# Network Intrusion Detection System (IDS)

A comprehensive, educational Network Intrusion Detection System built with Python that combines machine learning and rule-based approaches to detect network anomalies and potential cyber attacks.

## 🎯 Project Overview

This IDS project is designed for cybersecurity education and portfolio demonstration. It captures live network packets, extracts meaningful features, and uses both machine learning algorithms and rule-based detection to identify suspicious network activity in real-time.

### Key Features
- **Live Packet Capture**: Real-time network traffic monitoring using Scapy
- **Feature Extraction**: Automatic extraction of network traffic features
- **Machine Learning Detection**: Isolation Forest, One-Class SVM, and Random Forest algorithms
- **Rule-Based Detection**: Traditional signature-based intrusion detection
- **Real-Time Alerting**: Immediate notifications for suspicious activities
- **Interactive CLI**: Command-line interface for system control
- **Web Dashboard**: Optional Flask-based monitoring dashboard
- **Data Visualization**: Traffic analysis and anomaly visualization
- **Export Capabilities**: Save results to CSV and JSON formats
- **Sample Datasets**: Pre-generated test data for immediate testing

## Project Structure

```
IDS/
├── src/
│   ├── __init__.py
│   ├── packet_capture.py      # Network packet capture module
│   ├── feature_extractor.py   # Feature extraction from packets
│   ├── ml_detector.py         # ML-based anomaly detection
│   ├── rule_detector.py       # Rule-based detection system
│   ├── alert_system.py        # Alert generation and logging
│   ├── data_exporter.py       # CSV export functionality
│   └── visualization.py       # Traffic visualization
├── models/
│   └── trained_models/        # Saved ML models
├── data/
│   ├── captured_packets/      # Raw packet data
│   ├── extracted_features/    # Processed feature datasets
│   └── sample_data/          # Example datasets
├── logs/
│   └── detection_logs/        # Alert logs and reports
├── web_dashboard/
│   ├── app.py                # Flask web interface
│   ├── templates/
│   └── static/
├── tests/
│   └── test_modules.py       # Unit tests
├── utils/
│   └── helpers.py            # Utility functions
├── config.py                 # Configuration settings
├── main.py                   # Main application entry point
├── requirements.txt          # Python dependencies
└── README.md                # This file
```

## Installation

1. **Clone or download the project**
2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **For Windows users**: You may need to install Npcap/WinPcap for packet capture
   - Download from: https://npcap.com/

4. **For Linux users**: Run with sudo privileges for packet capture
   ```bash
   sudo python main.py
   ```

## Usage

### Basic Usage

1. **Run the main application**:
   ```bash
   python main.py
   ```

2. **Command-line options**:
   ```bash
   python main.py --mode ml --interface eth0 --duration 60
   python main.py --mode rule --interface wlan0 --output results.csv
   ```

3. **Web Dashboard** (optional):
   ```bash
   cd web_dashboard
   python app.py
   ```
   Then open browser to: http://localhost:5000

### Configuration

Edit `config.py` to customize:
- Network interface selection
- Detection thresholds
- ML model parameters
- Alert settings
- Logging preferences

## How It Works

### 1. Packet Capture
- Uses Scapy to capture live network packets
- Supports multiple network interfaces
- Filters packets based on protocols (TCP, UDP, ICMP)

### 2. Feature Extraction
Extracts 15+ network features including:
- Source/Destination IP addresses
- Source/Destination ports
- Protocol type
- Packet length
- Time intervals between packets
- TCP flags
- Payload size
- Flow duration

### 3. Anomaly Detection

#### Machine Learning Approach:
- **Isolation Forest**: Isolates anomalies by randomly selecting features
- **One-Class SVM**: Learns normal patterns and detects deviations
- **Random Forest**: Ensemble method for robust classification

#### Rule-based Approach:
- Port scanning detection
- Suspicious payload patterns
- Unusual protocol usage
- Traffic volume thresholds

### 4. Alert System
- Real-time console alerts
- Timestamped log entries
- Severity classification (Low, Medium, High)
- Optional email notifications

### 5. Visualization
- Traffic volume over time
- Protocol distribution
- Anomaly detection results
- Geographic IP mapping

## Educational Value

This project demonstrates:
- Network security fundamentals
- Machine learning for cybersecurity
- Real-time data processing
- Feature engineering techniques
- Anomaly detection algorithms
- Python networking libraries

## Security Considerations

- Run only on networks you own or have permission to monitor
- Be aware of privacy laws in your jurisdiction
- Use in isolated test environments when learning
- Never use for malicious purposes

## Troubleshooting

### Common Issues:

1. **Permission denied**: Run with administrator/sudo privileges
2. **No packets captured**: Check network interface selection
3. **ML model accuracy**: Ensure sufficient training data
4. **High memory usage**: Reduce packet buffer size in config

### Performance Tips:
- Use appropriate interface for your network
- Adjust sampling rate for high-traffic networks
- Consider using threading for real-time processing
- Regularly clean up log files

## Contributing

This is an educational project. Feel free to:
- Add new detection algorithms
- Improve visualization features
- Enhance the web dashboard
- Add more comprehensive testing

## License

This project is for educational purposes. Use responsibly and ethically.

## Disclaimer

This tool is for educational and authorized security testing only. Users are responsible for complying with all applicable laws and regulations.