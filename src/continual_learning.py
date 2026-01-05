"""
Continual learning module for model retraining.
Logs predictions and performs offline retraining periodically.
"""
import pandas as pd
import numpy as np
import os
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import threading
import time

logger = logging.getLogger(__name__)


class ContinualLearner:
    """
    Manages continual learning through offline retraining.
    Logs predictions and retrains the model periodically.
    """
    
    def __init__(self, 
                 log_dir: str = 'data/prediction_logs',
                 retrain_interval_hours: int = 24,
                 min_samples_for_retrain: int = 1000):
        """
        Initialize the continual learner.
        
        Args:
            log_dir: Directory to store prediction logs
            retrain_interval_hours: Hours between retraining attempts
            min_samples_for_retrain: Minimum samples needed for retraining
        """
        self.log_dir = log_dir
        self.retrain_interval_hours = retrain_interval_hours
        self.min_samples_for_retrain = min_samples_for_retrain
        
        # Create log directory
        os.makedirs(log_dir, exist_ok=True)
        
        # Retraining state
        self.last_retrain_time = None
        self.is_retraining = False
        self.retrain_thread = None
    
    def log_prediction(self, 
                      flow_features: Dict,
                      prediction: str,
                      confidence: float,
                      is_intrusion: bool,
                      ground_truth: Optional[str] = None):
        """
        Log a prediction for future retraining.
        
        Args:
            flow_features: Flow feature dictionary
            prediction: Prediction label ('Normal' or 'Malicious')
            confidence: Confidence score
            is_intrusion: Whether intrusion was detected
            ground_truth: Optional ground truth label (for validation)
        """
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'flow_features': flow_features,
            'prediction': prediction,
            'confidence': float(confidence),
            'is_intrusion': bool(is_intrusion),
            'ground_truth': ground_truth
        }
        
        # Save to daily log file
        date_str = datetime.now().strftime('%Y-%m-%d')
        log_file = os.path.join(self.log_dir, f'predictions_{date_str}.jsonl')
        
        try:
            with open(log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            logger.error(f"Error logging prediction: {e}")
    
    def get_logged_predictions(self, days: int = 7) -> pd.DataFrame:
        """
        Get logged predictions from recent days.
        
        Args:
            days: Number of days to look back
            
        Returns:
            DataFrame with logged predictions
        """
        all_entries = []
        cutoff_date = datetime.now() - timedelta(days=days)
        
        for i in range(days):
            date = datetime.now() - timedelta(days=i)
            date_str = date.strftime('%Y-%m-%d')
            log_file = os.path.join(self.log_dir, f'predictions_{date_str}.jsonl')
            
            if os.path.exists(log_file):
                try:
                    with open(log_file, 'r') as f:
                        for line in f:
                            entry = json.loads(line.strip())
                            entry_time = datetime.fromisoformat(entry['timestamp'])
                            if entry_time >= cutoff_date:
                                all_entries.append(entry)
                except Exception as e:
                    logger.error(f"Error reading log file {log_file}: {e}")
        
        if not all_entries:
            return pd.DataFrame()
        
        # Convert to DataFrame
        df = pd.DataFrame(all_entries)
        return df
    
    def prepare_training_data(self, days: int = 7) -> Optional[tuple]:
        """
        Prepare training data from logged predictions.
        
        Args:
            days: Number of days to include
            
        Returns:
            Tuple of (features_df, labels) or None if insufficient data
        """
        df = self.get_logged_predictions(days=days)
        
        if len(df) < self.min_samples_for_retrain:
            logger.info(f"Insufficient data for retraining: {len(df)} < {self.min_samples_for_retrain}")
            return None
        
        # Extract features
        features_list = []
        labels = []
        
        for _, row in df.iterrows():
            flow_features = row['flow_features']
            
            # Convert to feature vector (exclude non-numeric keys)
            feature_dict = {k: v for k, v in flow_features.items() 
                          if isinstance(v, (int, float)) and not np.isnan(v)}
            
            if feature_dict:
                features_list.append(feature_dict)
                
                # Use ground truth if available, otherwise use prediction
                if row.get('ground_truth'):
                    label = 1 if row['ground_truth'] == 'Malicious' else 0
                else:
                    label = 1 if row['is_intrusion'] else 0
                
                labels.append(label)
        
        if not features_list:
            return None
        
        # Convert to DataFrame
        features_df = pd.DataFrame(features_list)
        
        # Fill missing values
        features_df = features_df.fillna(0)
        
        # Ensure consistent feature set
        # (In production, you'd want to maintain a feature mapping)
        
        return features_df, np.array(labels)
    
    def should_retrain(self) -> bool:
        """Check if it's time to retrain."""
        if self.is_retraining:
            return False
        
        if self.last_retrain_time is None:
            return True
        
        time_since_retrain = datetime.now() - self.last_retrain_time
        return time_since_retrain >= timedelta(hours=self.retrain_interval_hours)
    
    def retrain_model(self, model, training_data: Optional[tuple] = None):
        """
        Retrain the model with new data.
        
        Args:
            model: The intrusion detection model to retrain
            training_data: Optional pre-prepared training data
        """
        if self.is_retraining:
            logger.warning("Retraining already in progress")
            return
        
        self.is_retraining = True
        
        try:
            logger.info("Starting model retraining...")
            
            # Prepare training data
            if training_data is None:
                training_data = self.prepare_training_data()
            
            if training_data is None:
                logger.warning("No training data available for retraining")
                return
            
            features_df, labels = training_data
            
            # Retrain model (this is a placeholder - actual implementation depends on model)
            # In practice, you would:
            # 1. Load existing model weights
            # 2. Fine-tune on new data
            # 3. Validate performance
            # 4. Save updated model
            
            logger.info(f"Retraining model with {len(features_df)} samples")
            
            # Placeholder: Actual retraining logic would go here
            # model.retrain(features_df, labels)
            
            self.last_retrain_time = datetime.now()
            logger.info("Model retraining completed")
            
        except Exception as e:
            logger.error(f"Error during retraining: {e}")
        finally:
            self.is_retraining = False
    
    def start_retrain_scheduler(self, model):
        """
        Start background thread for periodic retraining.
        
        Args:
            model: The intrusion detection model
        """
        def retrain_worker():
            while True:
                try:
                    if self.should_retrain():
                        self.retrain_model(model)
                    time.sleep(3600)  # Check every hour
                except Exception as e:
                    logger.error(f"Error in retrain scheduler: {e}")
                    time.sleep(3600)
        
        if self.retrain_thread is None or not self.retrain_thread.is_alive():
            self.retrain_thread = threading.Thread(target=retrain_worker, daemon=True)
            self.retrain_thread.start()
            logger.info("Started retrain scheduler")
    
    def get_statistics(self) -> Dict:
        """Get continual learning statistics."""
        df = self.get_logged_predictions(days=30)
        
        return {
            'total_logged_predictions': len(df) if not df.empty else 0,
            'last_retrain_time': self.last_retrain_time.isoformat() if self.last_retrain_time else None,
            'is_retraining': self.is_retraining,
            'samples_available_for_retrain': len(df) if not df.empty else 0,
            'can_retrain': len(df) >= self.min_samples_for_retrain if not df.empty else False
        }

