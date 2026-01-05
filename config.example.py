"""
Configuration file template for the Real-Time Intrusion Detection System.
Copy this file to config.py and modify as needed.
"""

# Network Interface Configuration
NETWORK_INTERFACE = None  # None for auto-detect, or specify like 'eth0', 'Wi-Fi', etc.

# Wireshark/Tshark Configuration
TSHARK_PATH_WINDOWS = 'C:\\Program Files\\Wireshark\\tshark.exe'
TSHARK_PATH_LINUX = 'tshark'  # Usually in PATH
TSHARK_PATH_MAC = 'tshark'    # Usually in PATH

# Model Configuration
MODEL_PATH = 'models/SecIDS-CNN.h5'
CONFIDENCE_THRESHOLD = 0.7  # Minimum confidence for intrusion alerts

# Flow Configuration
FLOW_TIMEOUT = 60  # Seconds before flow expires
DETECTION_INTERVAL = 5.0  # Seconds between detection cycles

# Web UI Configuration
WEB_UI_PORT = 5000
WEB_UI_HOST = '0.0.0.0'  # '127.0.0.1' for localhost only

# Continual Learning Configuration
LOG_DIRECTORY = 'data/prediction_logs'
RETRAIN_INTERVAL_HOURS = 24
MIN_SAMPLES_FOR_RETRAIN = 1000

# Logging Configuration
LOG_LEVEL = 'INFO'  # DEBUG, INFO, WARNING, ERROR
LOG_FILE = 'network_monitor.log'

# Capture Filter (BPF format)
# Examples:
#   '' - Capture all traffic
#   'tcp port 80' - HTTP traffic only
#   'host 192.168.1.1' - Traffic to/from specific host
CAPTURE_FILTER = ''

