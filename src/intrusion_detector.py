"""
CNN-based Intrusion Detection System (SecIDS-CNN) integration.
Provides real-time intrusion detection using deep learning.
"""
import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow import keras
from typing import Dict, List, Tuple, Optional
import os
import logging

logger = logging.getLogger(__name__)


class SecIDSCNN:
    """
    SecIDS-CNN model wrapper for intrusion detection.
    Classifies network traffic as normal or malicious.
    """
    
    def __init__(self, model_path: str = 'models/SecIDS-CNN.h5'):
        """
        Initialize the SecIDS-CNN model.
        
        Args:
            model_path: Path to the trained model file
        """
        self.model_path = model_path
        self.model = None
        self.feature_columns = None
        self.load_model()
        # Expected 78-feature order (approximate IDS-style schema)
        self.FEATURE_ORDER = [
            'flow_duration',
            'total_packets','forward_packets','backward_packets',
            'total_bytes','forward_bytes','backward_bytes',
            'packet_length_mean','packet_length_std','packet_length_min','packet_length_max',
            'fwd_packet_length_mean','fwd_packet_length_std','fwd_packet_length_min','fwd_packet_length_max',
            'bwd_packet_length_mean','bwd_packet_length_std','bwd_packet_length_min','bwd_packet_length_max',
            'mean_inter_arrival_time','std_inter_arrival_time','packet_rate',
            'tcp_flags_count','tcp_syn_count','tcp_ack_count','tcp_fin_count','tcp_rst_count',
            'fwd_packet_ratio','bwd_packet_ratio','fwd_byte_ratio','bwd_byte_ratio',
            # Derived extras to reach 78 features (normalized/scaled variants and simple composites)
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
    
    def load_model(self):
        """Load the SecIDS-CNN model from file."""
        try:
            if os.path.exists(self.model_path):
                self.model = keras.models.load_model(self.model_path)
                logger.info(f"Loaded SecIDS-CNN model from {self.model_path}")
            else:
                logger.warning(f"Model file not found at {self.model_path}. Creating a placeholder model.")
                self._create_placeholder_model()
        except Exception as e:
            logger.error(f"Error loading model: {e}. Creating a placeholder model.")
            self._create_placeholder_model()
    
    def _create_placeholder_model(self):
        """Create a placeholder CNN model if the original model is not available."""
        # Define a simple CNN architecture similar to SecIDS-CNN
        model = keras.Sequential([
            keras.layers.Input(shape=(1, 78)),  # Assuming 78 features
            keras.layers.Conv1D(32, 3, activation='relu'),
            keras.layers.MaxPooling1D(2),
            keras.layers.Conv1D(64, 3, activation='relu'),
            keras.layers.MaxPooling1D(2),
            keras.layers.Flatten(),
            keras.layers.Dense(128, activation='relu'),
            keras.layers.Dropout(0.5),
            keras.layers.Dense(64, activation='relu'),
            keras.layers.Dropout(0.5),
            keras.layers.Dense(2, activation='softmax')  # Binary classification: Normal/Malicious
        ])
        
        model.compile(
            optimizer='adam',
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )
        
        self.model = model
        logger.info("Created placeholder CNN model")
    
    def _prepare_features(self, df: pd.DataFrame) -> np.ndarray:
        """
        Prepare features for model input.
        
        Args:
            df: DataFrame with flow features
            
        Returns:
            Numpy array ready for model prediction
        """
        df_work = df.copy()
        # Basic protocol encoding
        prot = df_work.get('protocol')
        if prot is not None:
            df_work['protocol_tcp'] = (prot == 'TCP').astype(int)
            df_work['protocol_udp'] = (prot == 'UDP').astype(int)
            df_work['protocol_other'] = (~df_work['protocol_tcp'] & ~df_work['protocol_udp']).astype(int)
        else:
            df_work['protocol_tcp'] = 0
            df_work['protocol_udp'] = 0
            df_work['protocol_other'] = 1
        # Buckets for ports
        src_port_series = df_work.get('src_port', pd.Series(0, index=df_work.index))
        dst_port_series = df_work.get('dst_port', pd.Series(0, index=df_work.index))
        df_work['src_port_bucket'] = (src_port_series // 1024).fillna(0)
        df_work['dst_port_bucket'] = (dst_port_series // 1024).fillna(0)
        # Simple derived metrics
        df_work['packets_per_second'] = df_work.apply(lambda r: (r.get('total_packets',0) / r.get('flow_duration',1)) if r.get('flow_duration',0)>0 else 0, axis=1)
        df_work['bytes_per_second'] = df_work.apply(lambda r: (r.get('total_bytes',0) / r.get('flow_duration',1)) if r.get('flow_duration',0)>0 else 0, axis=1)
        df_work['avg_packet_length'] = df_work.get('packet_length_mean', pd.Series(0, index=df_work.index))
        df_work['avg_fwd_packet_length'] = df_work.get('fwd_packet_length_mean', pd.Series(0, index=df_work.index))
        df_work['avg_bwd_packet_length'] = df_work.get('bwd_packet_length_mean', pd.Series(0, index=df_work.index))
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
        # Get series for indicator calculations
        pkt_max = df_work.get('packet_length_max', pd.Series(0, index=df_work.index))
        pkt_mean = df_work.get('packet_length_mean', pd.Series(0, index=df_work.index))
        fwd_pkt_max = df_work.get('fwd_packet_length_max', pd.Series(0, index=df_work.index))
        fwd_pkt_mean = df_work.get('fwd_packet_length_mean', pd.Series(0, index=df_work.index))
        bwd_pkt_max = df_work.get('bwd_packet_length_max', pd.Series(0, index=df_work.index))
        bwd_pkt_mean = df_work.get('bwd_packet_length_mean', pd.Series(0, index=df_work.index))
        flow_dur = df_work.get('flow_duration', pd.Series(0, index=df_work.index))
        
        df_work['heavy_tail_indicator'] = (pkt_max > 3 * pkt_mean).astype(int)
        df_work['fwd_heavy_tail_indicator'] = (fwd_pkt_max > 3 * fwd_pkt_mean).astype(int)
        df_work['bwd_heavy_tail_indicator'] = (bwd_pkt_max > 3 * bwd_pkt_mean).astype(int)
        df_work['short_flow_indicator'] = (flow_dur < 1.0).astype(int)
        df_work['long_flow_indicator'] = (flow_dur > 60.0).astype(int)
        df_work['small_packet_indicator'] = (pkt_mean < 64).astype(int)
        df_work['large_packet_indicator'] = (pkt_mean > 1024).astype(int)
        # Normalized variants
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
        # Activity proxies
        df_work['fwd_activity'] = df_work.get('forward_packets', pd.Series(0, index=df_work.index)) + df_work.get('fwd_packet_length_mean', pd.Series(0, index=df_work.index))
        df_work['bwd_activity'] = df_work.get('backward_packets', pd.Series(0, index=df_work.index)) + df_work.get('bwd_packet_length_mean', pd.Series(0, index=df_work.index))
        # Packet size fractions (approx with mean/min/max)
        mean_len = df_work.get('packet_length_mean', pd.Series(0,index=df_work.index))
        max_len = df_work.get('packet_length_max', pd.Series(0,index=df_work.index)).replace(0,1)
        df_work['pkt_small_fraction'] = (mean_len < 128).astype(int)
        df_work['pkt_medium_fraction'] = ((mean_len >=128) & (mean_len <512)).astype(int)
        df_work['pkt_large_fraction'] = (mean_len >=512).astype(int)
        # Build ordered feature matrix of length 78
        for col in self.FEATURE_ORDER:
            if col not in df_work.columns:
                df_work[col] = 0
        features = df_work[self.FEATURE_ORDER].astype(float)
        arr = features.values
        n = arr.shape[0]
        input_shape = getattr(self.model, 'input_shape', None)
        
        # The model expects time series data with 10 timesteps and 1 feature per timestep
        # We need to reshape our 78 features into a time series format
        expected_timesteps = 10
        expected_features_per_timestep = 1
        
        def pad_or_truncate(x, target):
            f = x.shape[1]
            if f < target:
                pad = np.zeros((x.shape[0], target - f), dtype=np.float32)
                return np.concatenate([x.astype(np.float32), pad], axis=1)
            elif f > target:
                return x[:, :target].astype(np.float32)
            return x.astype(np.float32)
            
        if input_shape and len(input_shape) >= 3:
            # Model expects (batch, timesteps, features)
            # We need to reshape our features to match this
            if input_shape[1] == 10 and input_shape[2] == 1:
                # Model expects 10 timesteps with 1 feature each
                # We'll use the first 10 features as our time series
                arr_p = pad_or_truncate(arr, 10)
                features_array = arr_p.reshape(n, 10, 1)
            else:
                # Fallback: use the original approach but with correct dimensions
                arr_p = pad_or_truncate(arr, 10)
                features_array = arr_p.reshape(n, 10, 1)
        else:
            # Default to 10 timesteps with 1 feature each
            arr_p = pad_or_truncate(arr, 10)
            features_array = arr_p.reshape(n, 10, 1)  # Fixed: (batch, features, 1)
        return features_array
    
    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Predict intrusions from flow features.
        
        Args:
            df: DataFrame with flow features
            
        Returns:
            DataFrame with predictions and confidence scores
        """
        if df.empty:
            return pd.DataFrame()
        
        try:
            # Prepare features
            features = self._prepare_features(df)
            
            # Make predictions
            predictions = self.model.predict(features, verbose=0)
            
            # Extract class predictions and confidence scores
            predicted_classes = np.argmax(predictions, axis=1)
            confidence_scores = np.max(predictions, axis=1)
            
            # Create results DataFrame
            results = df.copy()
            results['prediction'] = ['Malicious' if c == 1 else 'Normal' for c in predicted_classes]
            results['confidence'] = confidence_scores
            results['is_intrusion'] = predicted_classes == 1
            
            return results
            
        except Exception as e:
            logger.error(f"Error during prediction: {e}", exc_info=True)
            # Return empty DataFrame with expected columns to prevent KeyError
            if df.empty:
                empty_df = pd.DataFrame(columns=['prediction', 'confidence', 'is_intrusion'])
            else:
                empty_df = df.copy()
                empty_df['prediction'] = ''
                empty_df['confidence'] = 0.0
                empty_df['is_intrusion'] = False
            return empty_df
    
    def predict_single(self, flow_features: Dict) -> Dict:
        """
        Predict intrusion for a single flow.
        
        Args:
            flow_features: Dictionary with flow features
            
        Returns:
            Dictionary with prediction results
        """
        df = pd.DataFrame([flow_features])
        results = self.predict(df)
        
        if not results.empty:
            return {
                'prediction': results.iloc[0]['prediction'],
                'confidence': float(results.iloc[0]['confidence']),
                'is_intrusion': bool(results.iloc[0]['is_intrusion'])
            }
        else:
            return {
                'prediction': 'Normal',
                'confidence': 0.5,
                'is_intrusion': False
            }


class IntrusionDetector:
    """
    High-level intrusion detection interface.
    Handles real-time detection and alerting.
    """
    
    def __init__(self, model_path: str = 'models/SecIDS-CNN.h5', 
                 confidence_threshold: float = 0.7):
        """
        Initialize the intrusion detector.
        
        Args:
            model_path: Path to the SecIDS-CNN model
            confidence_threshold: Minimum confidence for intrusion alerts
        """
        self.model = SecIDSCNN(model_path)
        self.confidence_threshold = confidence_threshold
        self.detection_history = []
    
    def detect(self, flow_features: pd.DataFrame) -> pd.DataFrame:
        """
        Detect intrusions in flow features.
        
        Args:
            flow_features: DataFrame with flow features
            
        Returns:
            DataFrame with detection results
        """
        if flow_features.empty:
            return pd.DataFrame()
        
        # Get predictions (use the model's predict method that handles feature preparation)
        results = self.model.predict(flow_features)
        
        # Check if results are empty or missing required columns
        if results.empty or 'is_intrusion' not in results.columns or 'confidence' not in results.columns:
            return pd.DataFrame()
        
        # Filter high-confidence intrusions
        intrusions = results[results['is_intrusion'] & 
                           (results['confidence'] >= self.confidence_threshold)].copy()
        
        # Log detections
        for _, row in intrusions.iterrows():
            detection = {
                'timestamp': pd.Timestamp.now(),
                'src_ip': row.get('src_ip', 'Unknown'),
                'dst_ip': row.get('dst_ip', 'Unknown'),
                'protocol': row.get('protocol', 'Unknown'),
                'confidence': row['confidence'],
                'flow_duration': row.get('flow_duration', 0),
                'total_packets': row.get('total_packets', 0)
            }
            self.detection_history.append(detection)
        
        return results
    
    def get_recent_detections(self, minutes: int = 60) -> List[Dict]:
        """
        Get recent intrusion detections.
        
        Args:
            minutes: Number of minutes to look back
            
        Returns:
            List of detection dictionaries
        """
        cutoff_time = pd.Timestamp.now() - pd.Timedelta(minutes=minutes)
        return [
            d for d in self.detection_history 
            if d['timestamp'] >= cutoff_time
        ]
    
    def get_statistics(self) -> Dict:
        """Get detection statistics."""
        if not self.detection_history:
            return {
                'total_detections': 0,
                'recent_detections': 0,
                'avg_confidence': 0.0
            }
        
        recent = self.get_recent_detections(minutes=60)
        
        return {
            'total_detections': len(self.detection_history),
            'recent_detections': len(recent),
            'avg_confidence': np.mean([d['confidence'] for d in recent]) if recent else 0.0
        }
