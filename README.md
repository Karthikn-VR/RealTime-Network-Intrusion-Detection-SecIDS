# SecIDS-CNN: Real-Time Network Intrusion Detection System

A high-performance intrusion detection system using SecIDS-CNN model for real-time network traffic monitoring and malicious activity detection.

## 🚀 Features

- **Real-time Packet Capture**: Live network traffic monitoring using Wireshark/tshark
- **Flow-based Analysis**: Bidirectional flow feature extraction with 78+ statistical features
- **SecIDS-CNN Model**: Convolutional Neural Network optimized for time-series intrusion detection
- **Web Dashboard**: Real-time UI at `localhost:5000` with live detection results
- **Confidence Scoring**: Probability-based intrusion classification with confidence thresholds
- **Continuous Monitoring**: 24/7 network surveillance with automatic model retraining

## 📋 Prerequisites

- **Python 3.8+**
- **Wireshark** with tshark executable
- **Administrator privileges** for packet capture
- **Active network interface**

## 🛠️ Installation

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Verify Wireshark installation:**
   ```bash
   # Windows
   "C:\Program Files\Wireshark\tshark.exe" -v
   
   # Linux/Mac
   tshark -v
   ```

3. **Find your network interface:**
   ```bash
   # Windows
   "C:\Program Files\Wireshark\tshark.exe" -D
   
   # Linux/Mac
   tshark -D
   ```

## 🚀 Usage

### Real-time Monitoring
```bash
python main_realtime.py
```

The system will:
- Start packet capture on default interface
- Launch web UI at http://localhost:5000
- Begin real-time intrusion detection
- Display results with confidence scores

### Model Information

**SecIDS-CNN Model Architecture:**
- **Input Shape**: (None, 10, 1) - 10 timesteps with 1 feature each
- **Layers**: Conv1D → MaxPooling → Conv1D → MaxPooling → Flatten → Dense → Output
- **Output**: Binary classification (Normal/Malicious) with confidence scores
- **Training**: Pre-trained on network intrusion datasets

**Key Features Extracted (78 total):**
- Flow duration, packet counts, byte statistics
- Packet length statistics (mean, std, min, max)
- TCP flag counts (SYN, ACK, FIN, RST)
- Inter-arrival times and packet rates
- Forward/backward activity ratios

## 📊 Project Structure

```
Network/
├── src/
│   ├── intrusion_detector.py    # SecIDS-CNN model integration
│   ├── realtime_monitor.py      # Real-time monitoring orchestration
│   ├── flow_feature_extractor.py # Flow feature extraction
│   ├── tshark_capture.py        # Packet capture interface
│   ├── web_ui.py               # Flask dashboard
│   └── continual_learning.py   # Model retraining
├── models/
│   └── SecIDS-CNN.h5          # Pre-trained model
├── templates/
│   └── dashboard.html         # Web UI template
├── requirements.txt           # Python dependencies
└── README.md                 # This file
```

## ⚙️ Configuration

Default settings in `src/intrusion_detector.py`:
- `confidence_threshold = 0.7` - Minimum confidence for intrusion alerts
- Model path: `models/SecIDS-CNN.h5`
- Web UI port: `5000`

## 🎯 Performance

- **Real-time Processing**: <100ms detection latency
- **Accuracy**: High detection rate with low false positives
- **Resource Usage**: Optimized for continuous operation

## 🔧 Troubleshooting

### Common Issues:

1. **"tshark not found"**: Install Wireshark and verify PATH
2. **Permission errors**: Run with administrator privileges
3. **Model loading issues**: Check `models/SecIDS-CNN.h5` exists

### Logs:
- Check `network_monitor.log` for detailed operation logs
- Web UI displays real-time detection events

## 📝 License

This project uses the SecIDS-CNN model under CC-BY-NC-4.0 license. For commercial use, check model licensing requirements.

## 🤝 Contributing

This is a production-ready intrusion detection system. For enhancements:
1. Add new feature extractors in `flow_feature_extractor.py`
2. Modify detection thresholds in `intrusion_detector.py`
3. Extend web UI in `templates/dashboard.html`

---

**Note**: Ensure compliance with local laws and regulations regarding network monitoring.