"""
Flow-level feature extraction module for intrusion detection.
Extracts meaningful features from network packets compatible with SecIDS-CNN.
"""
import pandas as pd
import numpy as np
from collections import defaultdict
from typing import Dict, List, Tuple
import time


class FlowFeatureExtractor:
    """
    Extracts flow-level features from packet data for intrusion detection.
    Features include: packet counts, byte statistics, flow duration, 
    protocol information, TCP flag counts, and timing characteristics.
    """
    
    def __init__(self, flow_timeout: int = 60):
        """
        Initialize the flow feature extractor.
        
        Args:
            flow_timeout: Timeout in seconds for flow expiration
        """
        self.flow_timeout = flow_timeout
        self.flows = defaultdict(lambda: {
            'packets': [],
            'start_time': None,
            'end_time': None,
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'protocol': None
        })
    
    def _get_flow_key(self, packet: Dict) -> Tuple:
        """Generate a flow key from packet information."""
        src_ip = packet.get('src_ip', '0.0.0.0')
        dst_ip = packet.get('dst_ip', '0.0.0.0')
        src_port = packet.get('src_port', 0)
        dst_port = packet.get('dst_port', 0)
        protocol = packet.get('protocol', 'UNKNOWN')
        
        # Use bidirectional flow key
        if src_ip < dst_ip or (src_ip == dst_ip and src_port < dst_port):
            return (src_ip, dst_ip, src_port, dst_port, protocol)
        else:
            return (dst_ip, src_ip, dst_port, src_port, protocol)
    
    def add_packet(self, packet: Dict):
        """
        Add a packet to the flow tracking system.
        
        Args:
            packet: Dictionary containing packet information
        """
        flow_key = self._get_flow_key(packet)
        flow = self.flows[flow_key]
        
        timestamp = packet.get('timestamp', time.time())
        packet_length = packet.get('length', 0)
        
        if flow['start_time'] is None:
            flow['start_time'] = timestamp
            flow['src_ip'] = packet.get('src_ip', '0.0.0.0')
            flow['dst_ip'] = packet.get('dst_ip', '0.0.0.0')
            flow['src_port'] = packet.get('src_port', 0)
            flow['dst_port'] = packet.get('dst_port', 0)
            flow['protocol'] = packet.get('protocol', 'UNKNOWN')
        
        flow['end_time'] = timestamp
        flow['packets'].append({
            'timestamp': timestamp,
            'length': packet_length,
            'tcp_flags': packet.get('tcp_flags', 0),
            'direction': packet.get('direction', 'forward')  # forward or backward
        })
    
    def _extract_flow_features(self, flow_key: Tuple, flow: Dict) -> Dict:
        """
        Extract features from a completed flow.
        
        Args:
            flow_key: Flow identifier tuple
            flow: Flow data dictionary
            
        Returns:
            Dictionary of extracted features
        """
        if not flow['packets']:
            return None
        
        packets = flow['packets']
        flow_duration = flow['end_time'] - flow['start_time']
        if flow_duration == 0:
            flow_duration = 0.001  # Avoid division by zero
        
        # Separate forward and backward packets
        forward_packets = [p for p in packets if p['direction'] == 'forward']
        backward_packets = [p for p in packets if p['direction'] == 'backward']
        
        # Basic statistics
        total_packets = len(packets)
        total_bytes = sum(p['length'] for p in packets)
        
        forward_packets_count = len(forward_packets)
        backward_packets_count = len(backward_packets)
        
        forward_bytes = sum(p['length'] for p in forward_packets)
        backward_bytes = sum(p['length'] for p in backward_packets)
        
        # Packet length statistics
        packet_lengths = [p['length'] for p in packets]
        forward_lengths = [p['length'] for p in forward_packets]
        backward_lengths = [p['length'] for p in backward_packets]
        
        # TCP flags (if TCP)
        tcp_flags = [p['tcp_flags'] for p in packets if p.get('tcp_flags', 0) > 0]
        
        # Timing features
        if len(packets) > 1:
            inter_arrival_times = [
                packets[i+1]['timestamp'] - packets[i]['timestamp'] 
                for i in range(len(packets) - 1)
            ]
            mean_iat = np.mean(inter_arrival_times) if inter_arrival_times else 0
            std_iat = np.std(inter_arrival_times) if inter_arrival_times else 0
        else:
            mean_iat = 0
            std_iat = 0
        
        # Build feature dictionary
        features = {
            # Flow identification
            'src_ip': flow['src_ip'],
            'dst_ip': flow['dst_ip'],
            'src_port': flow['src_port'],
            'dst_port': flow['dst_port'],
            'protocol': flow['protocol'],
            
            # Flow duration
            'flow_duration': flow_duration,
            
            # Packet counts
            'total_packets': total_packets,
            'forward_packets': forward_packets_count,
            'backward_packets': backward_packets_count,
            
            # Byte statistics
            'total_bytes': total_bytes,
            'forward_bytes': forward_bytes,
            'backward_bytes': backward_bytes,
            
            # Packet length statistics
            'packet_length_mean': np.mean(packet_lengths) if packet_lengths else 0,
            'packet_length_std': np.std(packet_lengths) if packet_lengths else 0,
            'packet_length_min': np.min(packet_lengths) if packet_lengths else 0,
            'packet_length_max': np.max(packet_lengths) if packet_lengths else 0,
            
            # Forward packet statistics
            'fwd_packet_length_mean': np.mean(forward_lengths) if forward_lengths else 0,
            'fwd_packet_length_std': np.std(forward_lengths) if forward_lengths else 0,
            'fwd_packet_length_min': np.min(forward_lengths) if forward_lengths else 0,
            'fwd_packet_length_max': np.max(forward_lengths) if forward_lengths else 0,
            
            # Backward packet statistics
            'bwd_packet_length_mean': np.mean(backward_lengths) if backward_lengths else 0,
            'bwd_packet_length_std': np.std(backward_lengths) if backward_lengths else 0,
            'bwd_packet_length_min': np.min(backward_lengths) if backward_lengths else 0,
            'bwd_packet_length_max': np.max(backward_lengths) if backward_lengths else 0,
            
            # Timing features
            'mean_inter_arrival_time': mean_iat,
            'std_inter_arrival_time': std_iat,
            'packet_rate': total_packets / flow_duration if flow_duration > 0 else 0,
            
            # TCP flags
            'tcp_flags_count': len(tcp_flags),
            'tcp_syn_count': sum(1 for f in tcp_flags if f & 0x02),
            'tcp_ack_count': sum(1 for f in tcp_flags if f & 0x10),
            'tcp_fin_count': sum(1 for f in tcp_flags if f & 0x01),
            'tcp_rst_count': sum(1 for f in tcp_flags if f & 0x04),
            
            # Ratios
            'fwd_packet_ratio': forward_packets_count / total_packets if total_packets > 0 else 0,
            'bwd_packet_ratio': backward_packets_count / total_packets if total_packets > 0 else 0,
            'fwd_byte_ratio': forward_bytes / total_bytes if total_bytes > 0 else 0,
            'bwd_byte_ratio': backward_bytes / total_bytes if total_bytes > 0 else 0,
        }
        
        return features
    
    def get_completed_flows(self, current_time: float = None) -> pd.DataFrame:
        """
        Get all completed flows as a DataFrame.
        
        Args:
            current_time: Current timestamp (defaults to current time)
            
        Returns:
            DataFrame with flow features
        """
        if current_time is None:
            current_time = time.time()
        
        completed_flows = []
        expired_keys = []
        
        for flow_key, flow in self.flows.items():
            # Check if flow is expired
            if flow['end_time'] and (current_time - flow['end_time']) > self.flow_timeout:
                features = self._extract_flow_features(flow_key, flow)
                if features:
                    completed_flows.append(features)
                expired_keys.append(flow_key)
        
        # Remove expired flows
        for key in expired_keys:
            del self.flows[key]
        
        if not completed_flows:
            return pd.DataFrame()
        
        return self._completed_flows_df(completed_flows)
    
    def get_all_flows(self) -> pd.DataFrame:
        """Get all flows (including active ones) as a DataFrame."""
        all_flows = []
        
        for flow_key, flow in self.flows.items():
            features = self._extract_flow_features(flow_key, flow)
            if features:
                all_flows.append(features)
        
        if not all_flows:
            return pd.DataFrame()
        
        return self._all_flows_df(all_flows)
    
    def reset(self):
        """Reset all flows."""
        self.flows.clear()
    
    def _align_to_secids_schema(self, df: pd.DataFrame) -> pd.DataFrame:
        feature_order = [
            'flow_duration',
            'total_packets','forward_packets','backward_packets',
            'total_bytes','forward_bytes','backward_bytes',
            'packet_length_mean','packet_length_std','packet_length_min','packet_length_max',
            'fwd_packet_length_mean','fwd_packet_length_std','fwd_packet_length_min','fwd_packet_length_max',
            'bwd_packet_length_mean','bwd_packet_length_std','bwd_packet_length_min','bwd_packet_length_max',
            'mean_inter_arrival_time','std_inter_arrival_time','packet_rate',
            'tcp_flags_count','tcp_syn_count','tcp_ack_count','tcp_fin_count','tcp_rst_count',
            'fwd_packet_ratio','bwd_packet_ratio','fwd_byte_ratio','bwd_byte_ratio',
            'packets_per_second','bytes_per_second',
            'avg_packet_length','avg_fwd_packet_length','avg_bwd_packet_length',
            'len_range','fwd_len_range','bwd_len_range',
            'fwd_to_bwd_packets_ratio','fwd_to_bwd_bytes_ratio',
            'pkt_len_coeff_var','fwd_pkt_len_coeff_var','bwd_pkt_len_coeff_var',
            'iat_coeff_var',
            'tcp_flag_syn_ack_ratio','tcp_flag_fin_rst_ratio',
            'bytes_per_packet','fwd_bytes_per_packet','bwd_bytes_per_packet',
            'heavy_tail_indicator','fwd_heavy_tail_indicator','bwd_heavy_tail_indicator',
            'short_flow_indicator','long_flow_indicator',
            'small_packet_indicator','large_packet_indicator',
            'normalized_total_packets','normalized_total_bytes',
            'normalized_packet_length_mean','normalized_packet_length_std',
            'normalized_fwd_packet_length_mean','normalized_fwd_packet_length_std',
            'normalized_bwd_packet_length_mean','normalized_bwd_packet_length_std',
            'normalized_mean_iat','normalized_std_iat',
            'normalized_packet_rate',
            'normalized_fwd_ratio_packets','normalized_bwd_ratio_packets',
            'normalized_fwd_ratio_bytes','normalized_bwd_ratio_bytes',
            'protocol_tcp','protocol_udp','protocol_other',
            'src_port_bucket','dst_port_bucket',
            'fwd_activity','bwd_activity',
            'pkt_small_fraction','pkt_medium_fraction','pkt_large_fraction'
        ]
        df_work = df.copy()
        prot = df_work.get('protocol')
        if prot is not None:
            df_work['protocol_tcp'] = (prot == 'TCP').astype(int)
            df_work['protocol_udp'] = (prot == 'UDP').astype(int)
            df_work['protocol_other'] = (~df_work['protocol_tcp'] & ~df_work['protocol_udp']).astype(int)
        else:
            df_work['protocol_tcp'] = 0
            df_work['protocol_udp'] = 0
            df_work['protocol_other'] = 1
        df_work['src_port_bucket'] = (df_work.get('src_port', 0) // 1024).fillna(0)
        df_work['dst_port_bucket'] = (df_work.get('dst_port', 0) // 1024).fillna(0)
        df_work['packets_per_second'] = df_work.apply(lambda r: (r.get('total_packets',0) / r.get('flow_duration',1)) if r.get('flow_duration',0)>0 else 0, axis=1)
        df_work['bytes_per_second'] = df_work.apply(lambda r: (r.get('total_bytes',0) / r.get('flow_duration',1)) if r.get('flow_duration',0)>0 else 0, axis=1)
        df_work['avg_packet_length'] = df_work.get('packet_length_mean', 0)
        df_work['avg_fwd_packet_length'] = df_work.get('fwd_packet_length_mean', 0)
        df_work['avg_bwd_packet_length'] = df_work.get('bwd_packet_length_mean', 0)
        df_work['len_range'] = df_work.get('packet_length_max',0) - df_work.get('packet_length_min',0)
        df_work['fwd_len_range'] = df_work.get('fwd_packet_length_max',0) - df_work.get('fwd_packet_length_min',0)
        df_work['bwd_len_range'] = df_work.get('bwd_packet_length_max',0) - df_work.get('bwd_packet_length_min',0)
        df_work['fwd_to_bwd_packets_ratio'] = df_work.apply(lambda r: (r.get('forward_packets',0) / max(r.get('backward_packets',0),1)), axis=1)
        df_work['fwd_to_bwd_bytes_ratio'] = df_work.apply(lambda r: (r.get('forward_bytes',0) / max(r.get('backward_bytes',0),1)), axis=1)
        df_work['pkt_len_coeff_var'] = df_work.apply(lambda r: (r.get('packet_length_std',0) / max(r.get('packet_length_mean',1),1)), axis=1)
        df_work['fwd_pkt_len_coeff_var'] = df_work.apply(lambda r: (r.get('fwd_packet_length_std',0) / max(r.get('fwd_packet_length_mean',1),1)), axis=1)
        df_work['bwd_pkt_len_coeff_var'] = df_work.apply(lambda r: (r.get('bwd_packet_length_std',0) / max(r.get('bwd_packet_length_mean',1),1)), axis=1)
        df_work['iat_coeff_var'] = df_work.apply(lambda r: (r.get('std_inter_arrival_time',0) / max(r.get('mean_inter_arrival_time',1),1)), axis=1)
        df_work['tcp_flag_syn_ack_ratio'] = df_work.apply(lambda r: (r.get('tcp_syn_count',0) / max(r.get('tcp_ack_count',0),1)), axis=1)
        df_work['tcp_flag_fin_rst_ratio'] = df_work.apply(lambda r: (r.get('tcp_fin_count',0) / max(r.get('tcp_rst_count',0),1)), axis=1)
        df_work['bytes_per_packet'] = df_work.apply(lambda r: (r.get('total_bytes',0) / max(r.get('total_packets',0),1)), axis=1)
        df_work['fwd_bytes_per_packet'] = df_work.apply(lambda r: (r.get('forward_bytes',0) / max(r.get('forward_packets',0),1)), axis=1)
        df_work['bwd_bytes_per_packet'] = df_work.apply(lambda r: (r.get('backward_bytes',0) / max(r.get('backward_packets',0),1)), axis=1)
        df_work['heavy_tail_indicator'] = (df_work.get('packet_length_max',0) > 3*df_work.get('packet_length_mean',0)).astype(int)
        df_work['fwd_heavy_tail_indicator'] = (df_work.get('fwd_packet_length_max',0) > 3*df_work.get('fwd_packet_length_mean',0)).astype(int)
        df_work['bwd_heavy_tail_indicator'] = (df_work.get('bwd_packet_length_max',0) > 3*df_work.get('bwd_packet_length_mean',0)).astype(int)
        df_work['short_flow_indicator'] = (df_work.get('flow_duration',0) < 1.0).astype(int)
        df_work['long_flow_indicator'] = (df_work.get('flow_duration',0) > 60.0).astype(int)
        df_work['small_packet_indicator'] = (df_work.get('packet_length_mean',0) < 64).astype(int)
        df_work['large_packet_indicator'] = (df_work.get('packet_length_mean',0) > 1024).astype(int)
        def norm_series(s):
            s = s.fillna(0)
            return (s - s.min()) / (s.max() - s.min() + 1e-8)
        df_work['normalized_total_packets'] = norm_series(df_work.get('total_packets', pd.Series(0,index=df_work.index)))
        df_work['normalized_total_bytes'] = norm_series(df_work.get('total_bytes', pd.Series(0,index=df_work.index)))
        df_work['normalized_packet_length_mean'] = norm_series(df_work.get('packet_length_mean', pd.Series(0,index=df_work.index)))
        df_work['normalized_packet_length_std'] = norm_series(df_work.get('packet_length_std', pd.Series(0,index=df_work.index)))
        df_work['normalized_fwd_packet_length_mean'] = norm_series(df_work.get('fwd_packet_length_mean', pd.Series(0,index=df_work.index)))
        df_work['normalized_fwd_packet_length_std'] = norm_series(df_work.get('fwd_packet_length_std', pd.Series(0,index=df_work.index)))
        df_work['normalized_bwd_packet_length_mean'] = norm_series(df_work.get('bwd_packet_length_mean', pd.Series(0,index=df_work.index)))
        df_work['normalized_bwd_packet_length_std'] = norm_series(df_work.get('bwd_packet_length_std', pd.Series(0,index=df_work.index)))
        df_work['normalized_mean_iat'] = norm_series(df_work.get('mean_inter_arrival_time', pd.Series(0,index=df_work.index)))
        df_work['normalized_std_iat'] = norm_series(df_work.get('std_inter_arrival_time', pd.Series(0,index=df_work.index)))
        df_work['normalized_packet_rate'] = norm_series(df_work.get('packet_rate', pd.Series(0,index=df_work.index)))
        df_work['normalized_fwd_ratio_packets'] = norm_series(df_work.get('fwd_packet_ratio', pd.Series(0,index=df_work.index)))
        df_work['normalized_bwd_ratio_packets'] = norm_series(df_work.get('bwd_packet_ratio', pd.Series(0,index=df_work.index)))
        df_work['normalized_fwd_ratio_bytes'] = norm_series(df_work.get('fwd_byte_ratio', pd.Series(0,index=df_work.index)))
        df_work['normalized_bwd_ratio_bytes'] = norm_series(df_work.get('bwd_byte_ratio', pd.Series(0,index=df_work.index)))
        df_work['fwd_activity'] = df_work.get('forward_packets',0) + df_work.get('fwd_packet_length_mean',0)
        df_work['bwd_activity'] = df_work.get('backward_packets',0) + df_work.get('bwd_packet_length_mean',0)
        mean_len = df_work.get('packet_length_mean', pd.Series(0,index=df_work.index))
        df_work['pkt_small_fraction'] = (mean_len < 128).astype(int)
        df_work['pkt_medium_fraction'] = ((mean_len >=128) & (mean_len <512)).astype(int)
        df_work['pkt_large_fraction'] = (mean_len >=512).astype(int)
        for col in feature_order:
            if col not in df_work.columns:
                df_work[col] = 0
        return df_work
    
    def _completed_flows_df(self, completed_flows: List[Dict]) -> pd.DataFrame:
        base_df = pd.DataFrame(completed_flows)
        if base_df.empty:
            return base_df
        return self._align_to_secids_schema(base_df)
    
    def _all_flows_df(self, all_flows: List[Dict]) -> pd.DataFrame:
        base_df = pd.DataFrame(all_flows)
        if base_df.empty:
            return base_df
        return self._align_to_secids_schema(base_df)
