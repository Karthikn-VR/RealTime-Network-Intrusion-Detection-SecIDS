import numpy as np
import torch
from typing import Optional

class TrafficPredictor:
    def __init__(self, model):
        self.model = model
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.model.to(self.device)
        
    def predict(self, X: np.ndarray) -> Optional[np.ndarray]:
        if len(X) == 0:
            return None
            
        try:
            self.model.eval()
            with torch.no_grad():
                X_tensor = torch.tensor(X, dtype=torch.float32).to(self.device)
                predictions = self.model(X_tensor).cpu().numpy()
            return predictions.flatten()
        except Exception as e:
            print(f"Prediction error: {e}")
            return None
    
    def prepare_input(self, data: np.ndarray, sequence_length: int = 10) -> np.ndarray:
        if len(data) < sequence_length:
            return np.array([])
            
        X = np.array([
            data[i:i + sequence_length] 
            for i in range(len(data) - sequence_length)
        ], dtype=np.float32)
        
        return X.reshape(-1, sequence_length, 1)