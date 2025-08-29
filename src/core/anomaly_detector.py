"""
Basic Network Anomaly Detection
Simpel Ml model to detect suspicious network activity
Author : [Aryan Pravin Sahu]
Description : Basic version - start with this simple structure
"""

from sklearn.ensemble import IsolationForest
import numpy as np

class BasicAnomalyDetector:
    def __init__(self):
        self.model = None
        self.is_trained = False

    def train(self, features):
        # Train Isolation Forest model
        print("Training anomaly detection model...")
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.model.fit(features)
        self.is_trained = True
        print("✅ Model trained successfully")

    def detect_anomalies(self, features):
        # Find anomalies in network
        if not self.is_trained:
            print("❌ Model not trained yet")
            return None

        predictions = self.model.predict(features)
        anomaly_count = np.sum(predictions == -1) 

        return{
            'total_packets': len(features),
            'anomalies_found': anomaly_count,
            'anomaly_rate': (anomaly_count / len(features))*100
        }
    
# Demo function
def test_basic_detection():

    # Importing previous modules
    from network_capture import NetworkCapture
    from data_processor import DataProcessor

    # Generate Test data
    capture = NetworkCapture()
    capture.start_monitoring()
    capture.simulate_packet_capture(50)

    # Process the data
    processor = DataProcessor()
    processor.load_from_capture(capture)
    processor.clean_data()
    features = processor.extract_features()

    # Run ML detection
    detector = BasicAnomalyDetector()
    detector.train(features)
    results = detector.detect_anomalies(features)

    print(f"🔍 Results: Found {results['anomalies_found']} suspicious packets")
    print(f"📊 Anomaly rate: {results['anomaly_rate']: .1f}%")

if __name__ == "__main__":
    test_basic_detection()


    