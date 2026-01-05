import matplotlib.pyplot as plt
import seaborn as sns
from typing import Optional, Dict
import numpy as np
import numpy as np
import pandas as pd



class Visualizer:
    def __init__(self):
        sns.set_style("whitegrid")
        plt.rcParams['figure.dpi'] = 100
        plt.rcParams['savefig.dpi'] = 100

    def plot_predictions(self, actual: np.ndarray, predicted: np.ndarray, 
                       filename: str = 'visualizations/traffic_prediction.png') -> None:
        if len(actual) == 0 or len(predicted) == 0:
            print("No data to plot")
            return
            
        plt.figure(figsize=(12, 6))
        plt.plot(actual, label='Actual', alpha=0.7)
        plt.plot(predicted, label='Predicted', alpha=0.7)
        plt.title('Network Traffic Prediction')
        plt.xlabel('Time Steps')
        plt.ylabel('Normalized Packet Size')
        plt.legend()
        plt.tight_layout()
        plt.savefig(filename)
        plt.close()

    def plot_training_history(self, history: Dict[str, list], 
                            filename: str = 'visualizations/training_history.png') -> None:
        if not history or 'loss' not in history:
            print("No training history to plot")
            return
            
        plt.figure(figsize=(12, 6))
        plt.plot(history['loss'], label='Training Loss')
        plt.title('Model Training History')
        plt.xlabel('Epoch')
        plt.ylabel('Loss (MSE)')
        plt.legend()
        plt.tight_layout()
        plt.savefig(filename)
        plt.close()

    def plot_feature_distributions(self, df: pd.DataFrame, 
                                 filename: str = 'visualizations/feature_distributions.png') -> None:
        if df.empty:
            print("No data for feature distributions")
            return
            
        numeric_cols = df.select_dtypes(include=np.number).columns
        if len(numeric_cols) == 0:
            return
            
        plt.figure(figsize=(12, 8))
        for i, col in enumerate(numeric_cols, 1):
            plt.subplot(len(numeric_cols)//2 + 1, 2, i)
            sns.histplot(df[col], kde=True)
            plt.title(f'Distribution of {col}')
        plt.tight_layout()
        plt.savefig(filename)
        plt.close()