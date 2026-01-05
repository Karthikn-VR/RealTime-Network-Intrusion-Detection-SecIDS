import asyncio
import logging
from src.data_collection import DataCollector
from src.feature_extraction import FeatureExtractor
from src.preprocessing import DataPreprocessor
from src.lstm_model import LSTMModel
from src.prediction import TrafficPredictor
from src.visualization import Visualizer
import numpy as np
import pandas as pd


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def main():
    try:
        logger.info("Starting network traffic analysis...")
        
        # 1. Data Collection
        logger.info("Starting data collection...")
        collector = DataCollector(capture_duration=30)
        traffic_data = await collector.capture_traffic()
        
        if traffic_data.empty:
            logger.warning("No traffic data captured. Using sample data.")
            # Create sample data if capture fails
            traffic_data = pd.DataFrame({
                'timestamp': range(100),
                'length': np.random.randint(40, 1500, 100),
                'protocol': ['TCP'] * 70 + ['UDP'] * 20 + ['ICMP'] * 10
            })
        
        logger.info(f"Collected {len(traffic_data)} packets")
        
        # 2. Feature Extraction
        logger.info("Extracting features...")
        extractor = FeatureExtractor()
        features = extractor.save_features()
        
        if features.empty:
            logger.error("Feature extraction failed. Exiting.")
            return
            
        # 3. Data Preprocessing
        logger.info("Preprocessing data...")
        preprocessor = DataPreprocessor(sequence_length=10)
        clean_data = preprocessor.clean_data(features)
        norm_data = preprocessor.normalize_data(clean_data)
        X, y = preprocessor.create_sequences(norm_data)
        
        if len(X) == 0 or len(y) == 0:
            logger.error("Insufficient data for sequences. Exiting.")
            return
            
        # Reshape for LSTM [samples, timesteps, features]
        X = X.reshape(-1, X.shape[1], 1)
        
        # 4. Model Training
        logger.info("Training LSTM model...")
        lstm = LSTMModel(input_size=1, hidden_size=64, num_layers=2)
        history = lstm.train_model(X, y, epochs=50, batch_size=16)
        
        # 5. Prediction
        logger.info("Making predictions...")
        predictor = TrafficPredictor(lstm)
        predictions = predictor.predict(X)
        
        if predictions is None:
            logger.error("Prediction failed. Exiting.")
            return
            
        # 6. Visualization
        logger.info("Generating visualizations...")
        viz = Visualizer()
        viz.plot_predictions(y[:100], predictions[:100])  # Plot first 100 points
        viz.plot_training_history(history)
        viz.plot_feature_distributions(features)
        
        logger.info("Network traffic analysis completed successfully!")
        
    except Exception as e:
        logger.error(f"Fatal error in main: {e}", exc_info=True)
        raise

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Program interrupted by user.")
    except Exception as e:
        logger.error(f"Unhandled exception: {e}", exc_info=True)