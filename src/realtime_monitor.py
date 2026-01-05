"""
Real-time network monitoring and intrusion detection orchestrator.
Coordinates packet capture, feature extraction, detection, and UI updates.
"""
import time
import threading
import logging
from typing import Optional
import pandas as pd
from datetime import datetime

from src.tshark_capture import TsharkCapture
from src.flow_feature_extractor import FlowFeatureExtractor
from src.intrusion_detector import IntrusionDetector
from src.traffic_analyzer import TrafficAnalyzer
from src.continual_learning import ContinualLearner
from src.web_ui import get_web_ui

logger = logging.getLogger(__name__)


class RealtimeMonitor:
    """
    Main orchestrator for real-time network monitoring and intrusion detection.
    """
    
    def __init__(self,
                 interface: Optional[str] = None,
                 tshark_path: str = 'C:\\Program Files\\Wireshark\\tshark.exe',
                 model_path: str = 'models/SecIDS-CNN.h5',
                 web_ui_port: int = 5000,
                 flow_timeout: int = 60,
                 detection_interval: float = 5.0):
        """
        Initialize the real-time monitor.
        
        Args:
            interface: Network interface name
            tshark_path: Path to tshark executable
            model_path: Path to SecIDS-CNN model
            web_ui_port: Port for web UI
            flow_timeout: Flow timeout in seconds
            detection_interval: Interval between detection cycles in seconds
        """
        # Initialize components
        self.capture = TsharkCapture(interface=interface, tshark_path=tshark_path)
        self.feature_extractor = FlowFeatureExtractor(flow_timeout=flow_timeout)
        self.detector = IntrusionDetector(model_path=model_path)
        self.analyzer = TrafficAnalyzer()
        self.learner = ContinualLearner()
        self.web_ui = get_web_ui(port=web_ui_port)
        
        # Monitoring state
        self.is_monitoring = False
        self.monitor_thread = None
        self.detection_interval = detection_interval
        
        # Statistics
        self.stats = {
            'packets_captured': 0,
            'flows_processed': 0,
            'intrusions_detected': 0,
            'start_time': None
        }
    
    def start_monitoring(self):
        """Start real-time monitoring."""
        if self.is_monitoring:
            logger.warning("Monitoring already running")
            return
        
        logger.info("Starting real-time network monitoring...")
        
        # Start packet capture
        self.capture.start_capture()
        
        # Start monitoring thread
        self.is_monitoring = True
        self.stats['start_time'] = datetime.now()
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        logger.info("Real-time monitoring started")
    
    def stop_monitoring(self):
        """Stop real-time monitoring."""
        logger.info("Stopping real-time network monitoring...")
        
        self.is_monitoring = False
        
        # Stop packet capture
        self.capture.stop_capture()
        
        # Wait for monitor thread
        if self.monitor_thread:
            self.monitor_thread.join(timeout=10)
        
        logger.info("Real-time monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop."""
        while self.is_monitoring:
            try:
                # Get captured packets
                packets = self.capture.get_packets(timeout=self.detection_interval)
                
                if packets:
                    self.stats['packets_captured'] += len(packets)
                    
                    # Add packets to flow extractor
                    for packet in packets:
                        self.feature_extractor.add_packet(packet)
                    
                    # Get completed flows
                    completed_flows = self.feature_extractor.get_completed_flows()
                    
                    if not completed_flows.empty:
                        self.stats['flows_processed'] += len(completed_flows)
                        
                        # Perform intrusion detection
                        detection_results = self.detector.detect(completed_flows)
                        
                        # If predictions are available, stream them
                        if not detection_results.empty and 'is_intrusion' in detection_results.columns:
                            intrusions = detection_results[detection_results['is_intrusion']]
                            self.stats['intrusions_detected'] += len(intrusions)
                            
                            # Stream all predictions to UI (Normal and Intrusion)
                            for _, row in detection_results.iterrows():
                                detection = {
                                    'src_ip': row.get('src_ip', 'Unknown'),
                                    'dst_ip': row.get('dst_ip', 'Unknown'),
                                    'protocol': row.get('protocol', 'Unknown'),
                                    'confidence': float(row.get('confidence', 0.0)),
                                    'flow_duration': float(row.get('flow_duration', 0)),
                                    'total_packets': int(row.get('total_packets', 0)),
                                    'prediction': row.get('prediction', 'Normal')
                                }
                                self.web_ui.add_detection(detection)
                                
                                flow_features = row.to_dict()
                                self.learner.log_prediction(
                                    flow_features=flow_features,
                                    prediction=row.get('prediction', 'Normal'),
                                    confidence=row.get('confidence', 0.0),
                                    is_intrusion=bool(row.get('is_intrusion', False))
                                )
                        
                        # Perform traffic analysis regardless
                        analysis = self.analyzer.analyze_flows(completed_flows)
                        
                        # Update web UI with statistics
                        stats_update = {
                            'timestamp': datetime.now().isoformat(),
                            'total_flows': analysis.get('total_flows', 0),
                            'total_packets': analysis.get('total_packets', 0),
                            'total_bytes': analysis.get('total_bytes', 0),
                            'packets_per_second': analysis.get('packets_per_second', 0),
                            'bytes_per_second': analysis.get('bytes_per_second', 0),
                            'protocol_distribution': analysis.get('protocol_distribution', {}),
                            'suspicious_patterns': analysis.get('suspicious_patterns', {}),
                            'intrusions_detected': self.stats['intrusions_detected'],
                            'flows_processed': self.stats['flows_processed'],
                            'packets_captured': self.stats['packets_captured']
                        }
                        
                        self.web_ui.update_traffic_stats(stats_update)
                    else:
                        # No completed flows yet; still emit live stats using active flows
                        all_flows = self.feature_extractor.get_all_flows()
                        analysis = self.analyzer.analyze_flows(all_flows)
                        stats_update = {
                            'timestamp': datetime.now().isoformat(),
                            'total_flows': analysis.get('total_flows', 0),
                            'total_packets': analysis.get('total_packets', 0),
                            'total_bytes': analysis.get('total_bytes', 0),
                            'packets_per_second': analysis.get('packets_per_second', 0),
                            'bytes_per_second': analysis.get('bytes_per_second', 0),
                            'protocol_distribution': analysis.get('protocol_distribution', {}),
                            'suspicious_patterns': analysis.get('suspicious_patterns', {}),
                            'intrusions_detected': self.stats['intrusions_detected'],
                            'flows_processed': self.stats['flows_processed'],
                            'packets_captured': self.stats['packets_captured']
                        }
                        self.web_ui.update_traffic_stats(stats_update)
                
                # Small sleep to prevent CPU spinning
                time.sleep(0.1)
                
            except Exception as e:
                logger.error(f"Error in monitor loop: {e}", exc_info=True)
                time.sleep(1)
    
    def get_statistics(self) -> dict:
        """Get monitoring statistics."""
        uptime = None
        if self.stats['start_time']:
            uptime = (datetime.now() - self.stats['start_time']).total_seconds()
        
        return {
            **self.stats,
            'uptime_seconds': uptime,
            'is_monitoring': self.is_monitoring,
            'detection_stats': self.detector.get_statistics(),
            'learning_stats': self.learner.get_statistics()
        }
    
    def start_continual_learning(self):
        """Start continual learning scheduler."""
        self.learner.start_retrain_scheduler(self.detector.model)
