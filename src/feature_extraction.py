import pandas as pd
import numpy as np
from typing import Optional

class FeatureExtractor:
    def __init__(self, data_path: str = 'data/captured_traffic.csv'):
        try:
            self.df = pd.read_csv(data_path, usecols=['timestamp', 'length', 'protocol'])
        except Exception as e:
            print(f"Error loading data: {e}")
            self.df = pd.DataFrame(columns=['timestamp', 'length', 'protocol'])

    def extract_features(self) -> pd.DataFrame:
        if self.df.empty:
            return pd.DataFrame()
            
        features = self.df.copy()
        
        # Calculate time-based features
        features['inter_arrival_time'] = features['timestamp'].diff().fillna(0)
        features['packet_rate'] = np.where(
            features['inter_arrival_time'] > 0,
            1 / features['inter_arrival_time'],
            0  # Instead of inf which causes problems
        )
        
        # Protocol one-hot encoding
        protocols = pd.get_dummies(features['protocol'], prefix='protocol')
        features = pd.concat([features, protocols], axis=1)
        
        # Rolling statistics
        features['rolling_avg_len'] = features['length'].rolling(5, min_periods=1).mean()
        features['rolling_std_len'] = features['length'].rolling(5, min_periods=1).std()
        
        return features.drop(columns=['protocol'], errors='ignore')

    def save_features(self, output_path: str = 'data/processed_features.csv') -> pd.DataFrame:
        features = self.extract_features()
        if not features.empty:
            features.to_csv(output_path, index=False)
        return features

if __name__ == "__main__":
    extractor = FeatureExtractor()
    features = extractor.save_features()
    print(features.head() if not features.empty else "No features extracted")