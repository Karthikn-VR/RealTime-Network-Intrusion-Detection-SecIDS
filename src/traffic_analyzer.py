"""
Network traffic analysis module.
Provides insights into traffic intensity, usage trends, and suspicious activity.
"""
import pandas as pd
import numpy as np
from typing import Dict, List, Tuple
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)


class TrafficAnalyzer:
    """
    Analyzes network traffic patterns and provides insights.
    """
    
    def __init__(self, window_size: int = 60):
        """
        Initialize the traffic analyzer.
        
        Args:
            window_size: Time window in seconds for trend analysis
        """
        self.window_size = window_size
        self.traffic_history = []
    
    def analyze_flows(self, flows: pd.DataFrame) -> Dict:
        """
        Analyze flow data and extract insights.
        
        Args:
            flows: DataFrame with flow features
            
        Returns:
            Dictionary with analysis results
        """
        if flows.empty:
            return self._empty_analysis()
        
        # Basic statistics
        total_flows = len(flows)
        total_packets = flows['total_packets'].sum() if 'total_packets' in flows.columns else 0
        total_bytes = flows['total_bytes'].sum() if 'total_bytes' in flows.columns else 0
        
        # Protocol distribution
        protocol_dist = flows['protocol'].value_counts().to_dict() if 'protocol' in flows.columns else {}
        
        # Top talkers (by bytes)
        if 'src_ip' in flows.columns and 'total_bytes' in flows.columns:
            top_sources = flows.groupby('src_ip')['total_bytes'].sum().nlargest(10).to_dict()
            top_destinations = flows.groupby('dst_ip')['total_bytes'].sum().nlargest(10).to_dict()
        else:
            top_sources = {}
            top_destinations = {}
        
        # Traffic intensity metrics
        if 'flow_duration' in flows.columns:
            avg_flow_duration = flows['flow_duration'].mean()
            total_duration = flows['flow_duration'].sum()
            packets_per_second = total_packets / total_duration if total_duration > 0 else 0
            bytes_per_second = total_bytes / total_duration if total_duration > 0 else 0
        else:
            avg_flow_duration = 0
            packets_per_second = 0
            bytes_per_second = 0
        
        # Suspicious patterns
        suspicious_patterns = self._detect_suspicious_patterns(flows)
        
        # Port analysis
        port_analysis = self._analyze_ports(flows)
        
        analysis = {
            'timestamp': pd.Timestamp.now(),
            'total_flows': total_flows,
            'total_packets': int(total_packets),
            'total_bytes': int(total_bytes),
            'protocol_distribution': protocol_dist,
            'top_sources': top_sources,
            'top_destinations': top_destinations,
            'avg_flow_duration': float(avg_flow_duration),
            'packets_per_second': float(packets_per_second),
            'bytes_per_second': float(bytes_per_second),
            'suspicious_patterns': suspicious_patterns,
            'port_analysis': port_analysis
        }
        
        # Store in history
        self.traffic_history.append(analysis)
        
        # Keep only recent history
        if len(self.traffic_history) > 1000:
            self.traffic_history = self.traffic_history[-1000:]
        
        return analysis
    
    def _detect_suspicious_patterns(self, flows: pd.DataFrame) -> Dict:
        """Detect suspicious traffic patterns."""
        patterns = {
            'high_packet_count': 0,
            'high_byte_count': 0,
            'long_duration': 0,
            'unusual_ports': 0,
            'rapid_connections': 0
        }
        
        if flows.empty:
            return patterns
        
        # High packet count flows (>1000 packets)
        if 'total_packets' in flows.columns:
            patterns['high_packet_count'] = int((flows['total_packets'] > 1000).sum())
        
        # High byte count flows (>10MB)
        if 'total_bytes' in flows.columns:
            patterns['high_byte_count'] = int((flows['total_bytes'] > 10_000_000).sum())
        
        # Long duration flows (>5 minutes)
        if 'flow_duration' in flows.columns:
            patterns['long_duration'] = int((flows['flow_duration'] > 300).sum())
        
        # Unusual ports (non-standard ports)
        if 'dst_port' in flows.columns:
            common_ports = {80, 443, 22, 21, 25, 53, 110, 143, 993, 995}
            unusual = flows[~flows['dst_port'].isin(common_ports)]
            patterns['unusual_ports'] = len(unusual)
        
        # Rapid connections (many flows from same source)
        if 'src_ip' in flows.columns:
            source_counts = flows['src_ip'].value_counts()
            patterns['rapid_connections'] = int((source_counts > 50).sum())
        
        return patterns
    
    def _analyze_ports(self, flows: pd.DataFrame) -> Dict:
        """Analyze port usage patterns."""
        if flows.empty or 'dst_port' not in flows.columns:
            return {}
        
        port_counts = flows['dst_port'].value_counts().head(20).to_dict()
        return {str(k): int(v) for k, v in port_counts.items()}
    
    def _empty_analysis(self) -> Dict:
        """Return empty analysis structure."""
        return {
            'timestamp': pd.Timestamp.now(),
            'total_flows': 0,
            'total_packets': 0,
            'total_bytes': 0,
            'protocol_distribution': {},
            'top_sources': {},
            'top_destinations': {},
            'avg_flow_duration': 0.0,
            'packets_per_second': 0.0,
            'bytes_per_second': 0.0,
            'suspicious_patterns': {},
            'port_analysis': {}
        }
    
    def get_trends(self, minutes: int = 60) -> Dict:
        """
        Get traffic trends over time.
        
        Args:
            minutes: Number of minutes to analyze
            
        Returns:
            Dictionary with trend data
        """
        if not self.traffic_history:
            return {}
        
        cutoff_time = pd.Timestamp.now() - pd.Timedelta(minutes=minutes)
        recent_history = [
            h for h in self.traffic_history 
            if h['timestamp'] >= cutoff_time
        ]
        
        if not recent_history:
            return {}
        
        # Extract metrics over time
        timestamps = [h['timestamp'] for h in recent_history]
        packet_counts = [h['total_packets'] for h in recent_history]
        byte_counts = [h['total_bytes'] for h in recent_history]
        flow_counts = [h['total_flows'] for h in recent_history]
        
        # Calculate trends
        packet_trend = np.polyfit(range(len(packet_counts)), packet_counts, 1)[0] if len(packet_counts) > 1 else 0
        byte_trend = np.polyfit(range(len(byte_counts)), byte_counts, 1)[0] if len(byte_counts) > 1 else 0
        flow_trend = np.polyfit(range(len(flow_counts)), flow_counts, 1)[0] if len(flow_counts) > 1 else 0
        
        return {
            'time_range': {
                'start': timestamps[0].isoformat() if timestamps else None,
                'end': timestamps[-1].isoformat() if timestamps else None
            },
            'packet_trend': float(packet_trend),
            'byte_trend': float(byte_trend),
            'flow_trend': float(flow_trend),
            'avg_packets_per_minute': float(np.mean(packet_counts)) if packet_counts else 0,
            'avg_bytes_per_minute': float(np.mean(byte_counts)) if byte_counts else 0,
            'avg_flows_per_minute': float(np.mean(flow_counts)) if flow_counts else 0
        }
    
    def get_summary(self) -> Dict:
        """Get a summary of current traffic state."""
        if not self.traffic_history:
            return self._empty_analysis()
        
        # Get most recent analysis
        latest = self.traffic_history[-1]
        
        # Add trend information
        trends = self.get_trends(minutes=60)
        latest['trends'] = trends
        
        return latest

