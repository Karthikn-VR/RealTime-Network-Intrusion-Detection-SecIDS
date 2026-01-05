import pandas as pd
import numpy as np
from sklearn.preprocessing import MinMaxScaler
from typing import Tuple

class DataPreprocessor:
    def __init__(self, sequence_length: int = 10):
        self.sequence_length = sequence_length
        self.scaler = MinMaxScaler(feature_range=(0, 1))
        self.feature_columns = ['length', 'inter_arrival_time', 'packet_rate']

    def clean_data(self, df: pd.DataFrame = None) -> pd.DataFrame:
        try:
            if df is None:
                df = pd.read_csv('data/processed_features.csv')
            
            # Handle infinite values
            df = df.replace([np.inf, -np.inf], np.nan)
            
            # Drop rows with missing values
            df = df.dropna()
            
            return df
        except Exception as e:
            print(f"Data cleaning error: {e}")
            return pd.DataFrame()

    def normalize_data(self, df: pd.DataFrame = None) -> pd.DataFrame:
        try:
            if df is None:
                df = self.clean_data()
            
            if df.empty:
                return pd.DataFrame()
                
            # Select and normalize features
            features = df[self.feature_columns]
            normalized = self.scaler.fit_transform(features)
            
            return pd.DataFrame(normalized, columns=self.feature_columns)
        except Exception as e:
            print(f"Normalization error: {e}")
            return pd.DataFrame()

    def create_sequences(self, df: pd.DataFrame = None) -> Tuple[np.ndarray, np.ndarray]:
        try:
            if df is None:
                df = self.normalize_data()
            
            if df.empty or len(df) < self.sequence_length + 1:
                return np.array([]), np.array([])
                
            data = df['length'].values  # Using length as primary feature
            X, y = [], []
            
            for i in range(len(data) - self.sequence_length):
                X.append(data[i:i + self.sequence_length])
                y.append(data[i + self.sequence_length])
                
            return np.array(X), np.array(y)
        except Exception as e:
            print(f"Sequence creation error: {e}")
            return np.array([]), np.array([])