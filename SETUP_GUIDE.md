# Network Intrusion Detection System - Setup Guide

## 🚀 Quick Start Guide

This guide will help you set up and run the Network Intrusion Detection System (IDS) project in just a few minutes.

## Prerequisites

### System Requirements
- **Python**: 3.7 or higher
- **Operating System**: Windows, Linux, or macOS
- **Network Access**: Administrator/root privileges for packet capture
- **Memory**: Minimum 4GB RAM (8GB recommended)
- **Storage**: 2GB free space

### Required Privileges
For packet capture functionality, you need:
- **Windows**: Run as Administrator
- **Linux/macOS**: Run with sudo or as root

## Installation Steps

### Step 1: Navigate to Project Directory
```bash
cd c:\Users\krish\Downloads\IDS
```

### Step 2: Install Dependencies
```bash
# Install all required packages
pip install -r requirements.txt

# Verify installation
python -c "import scapy, sklearn, pandas, numpy, matplotlib, flask; print('All packages installed successfully!')"
```

### Step 3: Generate Sample Data (Optional but Recommended)
```bash
# Generate test datasets for immediate testing
python sample_data_generator.py
```

This creates sample datasets in the `sample_data/` directory:
- `normal_traffic.csv` - Normal network traffic
- `malicious_traffic.csv` - Attack traffic patterns
- `mixed_traffic.csv` - Combined dataset
- Various test files for different scenarios

### Step 4: Test Basic Functionality
```bash
# Test ML model training
python main.py --mode train --dataset sample_data/mixed_traffic.csv --model-type isolation_forest

# Test detection on sample data
python main.py --mode detect --input sample_data/mixed_traffic.csv --output results.json
```

## Running the IDS System

### Method 1: Interactive CLI (Recommended for Beginners)
```bash
# Start interactive command-line interface
python cli.py

# Available commands in CLI:
# capture, train, detect, analyze, visualize, report, status, help
```

### Method 2: Command Line Arguments
```bash
# Basic packet capture
python main.py --mode capture --duration 60 --output capture_results.json

# Train ML model
python main.py --mode train --dataset sample_data/mixed_traffic.csv --model-output models/my_model.pkl

# Run detection
python main.py --mode detect --model models/my_model.pkl --duration 300

# Start web dashboard
python main.py --mode web --port 5000
```

### Method 3: Web Dashboard
```bash
# Start Flask web interface
python web_dashboard.py

# Access dashboard at: http://localhost:5000
```

## Common Usage Scenarios

### Scenario 1: Educational Testing
```bash
# Generate and analyze sample data
python sample_data_generator.py
python cli.py analyze --input sample_data/mixed_traffic.csv --output analysis_report.html
```

### Scenario 2: Live Network Monitoring
```bash
# Capture live traffic (requires admin privileges)
sudo python main.py --mode capture --interface eth0 --duration 300

# Run real-time detection
sudo python cli.py detect --mode hybrid --duration 600
```

### Scenario 3: Model Development
```bash
# Train different ML models
python cli.py train --dataset sample_data/mixed_traffic.csv --model-type isolation_forest
python cli.py train --dataset sample_data/mixed_traffic.csv --model-type one_class_svm
python cli.py train --dataset sample_data/mixed_traffic.csv --model-type random_forest

# Compare model performance
python cli.py evaluate --models-dir models/ --test-data sample_data/test_data.csv
```

## Configuration Options

### Basic Configuration
Edit `config.py` to customize:
- Network interface settings
- Detection thresholds
- Alert configurations
- Model parameters
- Logging settings

### Common Settings to Modify
```python
# Network Configuration
NETWORK_INTERFACE = "eth0"  # Change to your network interface
CAPTURE_DURATION = 300      # Capture duration in seconds

# Detection Thresholds
ANOMALY_THRESHOLD = 0.7     # ML detection threshold (0.0-1.0)
PORT_SCAN_THRESHOLD = 50    # Port scan detection threshold
DDOS_PACKET_RATE = 1000     # DDoS detection packet rate

# Alert Settings
ALERT_RATE_LIMIT = 10       # Maximum alerts per minute
ENABLE_EMAIL_ALERTS = False # Enable/disable email notifications
```

## Troubleshooting

### Common Issues and Solutions

#### 1. Permission Denied (Packet Capture)
```bash
# Linux/macOS
sudo python main.py --mode capture

# Windows: Right-click -> Run as Administrator
python main.py --mode capture
```

#### 2. Missing Dependencies
```bash
# Reinstall all packages
pip uninstall scapy scikit-learn pandas numpy matplotlib flask
pip install -r requirements.txt

# Check Python version
python --version  # Should be 3.7+
```

#### 3. No Network Interface Found
```bash
# List available interfaces
python -c "from scapy.all import get_if_list; print(get_if_list())"

# Use specific interface
python main.py --mode capture --interface "Ethernet"  # Windows
python main.py --mode capture --interface "eth0"      # Linux
```

#### 4. Model Training Errors
```bash
# Check dataset format
python -c "import pandas as pd; df=pd.read_csv('sample_data/mixed_traffic.csv'); print(df.head())"

# Validate dataset
python -c "from sample_data_generator import TestingUtilities; t=TestingUtilities(); print(t.validate_dataset(pd.read_csv('sample_data/mixed_traffic.csv').to_dict('records')))"
```

#### 5. Web Dashboard Issues
```bash
# Check if port is available
python -c "import socket; s=socket.socket(); s.bind(('localhost', 5000)); s.close(); print('Port 5000 is available')"

# Use different port
python main.py --mode web --port 8080
```

### Getting Help

#### Built-in Help
```bash
# General help
python main.py --help

# CLI help
python cli.py help

# Specific command help
python cli.py capture --help
```

#### Debug Mode
```bash
# Enable debug logging
export IDS_DEBUG=true  # Linux/macOS
set IDS_DEBUG=true     # Windows

python main.py --mode capture --debug
```

#### Check System Status
```bash
python cli.py status
```

## Performance Tips

### For Better Performance
1. **Reduce packet buffer size** for high-traffic networks
2. **Lower detection frequency** to reduce CPU usage
3. **Use sampling** for very large datasets
4. **Optimize ML parameters** in config.py
5. **Run on dedicated hardware** for production use

### For Educational Use
1. **Start with sample data** before live capture
2. **Use shorter durations** for initial testing
3. **Enable visualization** to understand detection patterns
4. **Experiment with different ML models**
5. **Try various attack scenarios** with generated data

## Next Steps

### For Learning
1. **Examine the code**: Study each module to understand how it works
2. **Modify detection rules**: Add custom signatures in `rule_detector.py`
3. **Experiment with features**: Try different feature combinations in `feature_extractor.py`
4. **Create custom attacks**: Generate new attack patterns in `sample_data_generator.py`

### For Portfolio Development
1. **Add new ML models**: Implement additional algorithms
2. **Create custom dashboards**: Build specialized visualizations
3. **Integrate with SIEM**: Connect to security information systems
4. **Add machine learning pipelines**: Implement automated model training

### For Production Use
1. **Implement proper authentication**: Add user management
2. **Set up monitoring**: Add system health monitoring
3. **Create backup systems**: Implement data backup and recovery
4. **Add compliance features**: Meet regulatory requirements

## Support and Resources

### Documentation
- Full project documentation in README.md
- Code comments and docstrings
- Configuration examples in config.py

### Community
- Check for updates and improvements
- Contribute to the project
- Share your experiences and modifications

---

**🎉 Congratulations!** Your Network Intrusion Detection System is now ready to use. Start with the sample data to familiarize yourself with the system, then move on to live network monitoring.