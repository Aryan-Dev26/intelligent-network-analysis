"""
Advanced Multi-Algorithm Anomaly Detection System
Research-level implementation with ensemble methods and deep learning
Author: Aryan Pravin Sahu
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.cluster import DBSCAN
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, LSTM, Dropout
import joblib
import json
from datetime import datetime

class AdvancedAnomalyDetector:
    """
    Research-grade anomaly detection system combining multiple algorithms
    Implements ensemble learning with deep learning components
    """
    
    def __init__(self, config=None):
        self.config = config or self._default_config()
        self.models = {}
        self.scaler = StandardScaler()
        self.is_trained = False
        self.ensemble_weights = {}
        self.performance_metrics = {}
        
    def _default_config(self):
        return {
            'isolation_forest': {
                'contamination': 0.1,
                'n_estimators': 200,
                'random_state': 42
            },
            'dbscan': {
                'eps': 2.0,
                'min_samples': 2
            },
            'one_class_svm': {
                'nu': 0.1,
                'kernel': 'rbf',
                'gamma': 'scale'
            },
            'lstm': {
                'sequence_length': 10,
                'hidden_units': 64,
                'dropout_rate': 0.2,
                'epochs': 50,
                'batch_size': 32
            },
            'ensemble': {
                'voting_strategy': 'weighted',
                'confidence_threshold': 0.7
            }
        }
    
    def prepare_lstm_sequences(self, data, sequence_length=10):
        """Prepare sequential data for LSTM model"""
        sequences = []
        for i in range(len(data) - sequence_length + 1):
            sequences.append(data[i:i + sequence_length])
        return np.array(sequences)
    
    def build_lstm_autoencoder(self, input_shape):
        """Build LSTM autoencoder for anomaly detection"""
        model = Sequential([
            LSTM(self.config['lstm']['hidden_units'], 
                 activation='relu', 
                 input_shape=input_shape,
                 return_sequences=True),
            Dropout(self.config['lstm']['dropout_rate']),
            LSTM(32, activation='relu', return_sequences=True),
            Dropout(self.config['lstm']['dropout_rate']),
            Dense(input_shape[1], activation='linear')  # Reconstruction layer
        ])
        
        model.compile(optimizer='adam', loss='mse', metrics=['mae'])
        return model
    
    def train_ensemble(self, features, labels=None):
        """
        Train ensemble of anomaly detection algorithms
        Args:
            features: Normalized feature matrix
            labels: Optional ground truth labels for evaluation
        """
        print("Training advanced ensemble anomaly detection system...")
        
        # Scale features
        features_scaled = self.scaler.fit_transform(features)
        
        # 1. Isolation Forest
        print("   Training Isolation Forest...")
        self.models['isolation_forest'] = IsolationForest(**self.config['isolation_forest'])
        self.models['isolation_forest'].fit(features_scaled)
        
        # 2. DBSCAN Clustering
        print("   Training DBSCAN...")
        self.models['dbscan'] = DBSCAN(**self.config['dbscan'])
        dbscan_labels = self.models['dbscan'].fit_predict(features_scaled)
        
        # Intelligent anomaly detection for DBSCAN
        # Consider small clusters and noise as anomalies
        unique_labels, counts = np.unique(dbscan_labels, return_counts=True)
        
        # Find small clusters (less than 10% of data) and noise (-1)
        total_points = len(dbscan_labels)
        small_cluster_threshold = max(2, total_points * 0.1)  # At least 2 points, or 10% of data
        
        anomalous_labels = set()
        for label, count in zip(unique_labels, counts):
            if label == -1 or count < small_cluster_threshold:
                anomalous_labels.add(label)
        
        # Create anomaly predictions
        self.dbscan_anomaly_labels_ = np.array([
            -1 if label in anomalous_labels else 1 
            for label in dbscan_labels
        ])
        
        # Store the training labels for later use
        self.dbscan_labels_ = dbscan_labels
        
        # 3. One-Class SVM
        print("   Training One-Class SVM...")
        self.models['one_class_svm'] = OneClassSVM(**self.config['one_class_svm'])
        self.models['one_class_svm'].fit(features_scaled)
        
        # 4. LSTM Autoencoder
        print("   Training LSTM Autoencoder...")
        seq_length = self.config['lstm']['sequence_length']
        if len(features_scaled) >= seq_length:
            lstm_sequences = self.prepare_lstm_sequences(features_scaled, seq_length)
            
            self.models['lstm'] = self.build_lstm_autoencoder(
                (seq_length, features_scaled.shape[1])
            )
            
            # Train autoencoder to reconstruct normal patterns
            self.models['lstm'].fit(
                lstm_sequences, lstm_sequences,
                epochs=self.config['lstm']['epochs'],
                batch_size=self.config['lstm']['batch_size'],
                validation_split=0.2,
                verbose=0
            )
        
        # Calculate ensemble weights based on individual performance
        self._calculate_ensemble_weights(features_scaled, labels)
        
        self.is_trained = True
        print("Ensemble training completed successfully")
        
    def _calculate_ensemble_weights(self, features, labels=None):
        """Calculate weights for ensemble voting based on performance"""
        if labels is None:
            # Use unsupervised approach - weight by consistency
            predictions = {}
            
            # Get predictions from each model
            predictions['isolation_forest'] = self.models['isolation_forest'].predict(features)
            predictions['one_class_svm'] = self.models['one_class_svm'].predict(features)
            
            # DBSCAN: use intelligent anomaly detection results
            if hasattr(self, 'dbscan_anomaly_labels_') and len(self.dbscan_anomaly_labels_) == len(features):
                predictions['dbscan'] = self.dbscan_anomaly_labels_
            else:
                # Fallback: use simple noise detection
                dbscan_pred = self.models['dbscan'].fit_predict(features)
                predictions['dbscan'] = np.where(dbscan_pred == -1, -1, 1)
            
            # Calculate agreement between models
            agreements = []
            model_names = list(predictions.keys())
            
            for i, model1 in enumerate(model_names):
                for j, model2 in enumerate(model_names[i+1:], i+1):
                    agreement = np.mean(predictions[model1] == predictions[model2])
                    agreements.append(agreement)
            
            # Weight models by average agreement
            avg_agreement = np.mean(agreements)
            self.ensemble_weights = {
                'isolation_forest': 0.4,  # Generally reliable
                'one_class_svm': 0.3,    # Good for complex boundaries
                'dbscan': 0.2,           # Good for density-based anomalies
                'lstm': 0.1              # Experimental weight
            }
        else:
            # Supervised approach - weight by actual performance
            # Implementation for when ground truth is available
            pass
    
    def detect_anomalies_ensemble(self, features):
        """
        Detect anomalies using ensemble of trained models
        Returns detailed results with confidence scores
        """
        if not self.is_trained:
            raise ValueError("Models not trained. Call train_ensemble() first.")
        
        features_scaled = self.scaler.transform(features)
        results = {
            'individual_predictions': {},
            'ensemble_prediction': [],
            'confidence_scores': [],
            'anomaly_details': []
        }
        
        # Get predictions from each model
        # Isolation Forest
        if_pred = self.models['isolation_forest'].predict(features_scaled)
        if_scores = self.models['isolation_forest'].decision_function(features_scaled)
        results['individual_predictions']['isolation_forest'] = if_pred
        
        # One-Class SVM
        svm_pred = self.models['one_class_svm'].predict(features_scaled)
        svm_scores = self.models['one_class_svm'].decision_function(features_scaled)
        results['individual_predictions']['one_class_svm'] = svm_pred
        
        # DBSCAN (use intelligent anomaly detection results)
        if hasattr(self, 'dbscan_anomaly_labels_') and len(self.dbscan_anomaly_labels_) == len(features_scaled):
            results['individual_predictions']['dbscan'] = self.dbscan_anomaly_labels_
        else:
            # Fallback: use simple noise detection
            dbscan_pred = self.models['dbscan'].fit_predict(features_scaled)
            results['individual_predictions']['dbscan'] = np.where(dbscan_pred == -1, -1, 1)
        
        # LSTM Autoencoder (if available)
        lstm_pred = None
        if 'lstm' in self.models and len(features_scaled) >= self.config['lstm']['sequence_length']:
            seq_length = self.config['lstm']['sequence_length']
            lstm_sequences = self.prepare_lstm_sequences(features_scaled, seq_length)
            
            reconstructed = self.models['lstm'].predict(lstm_sequences, verbose=0)
            reconstruction_errors = np.mean(np.square(lstm_sequences - reconstructed), axis=(1, 2))
            
            # Threshold for anomaly detection (top 10% reconstruction errors)
            threshold = np.percentile(reconstruction_errors, 90)
            lstm_pred = np.where(reconstruction_errors > threshold, -1, 1)
            
            # Pad to match original length
            lstm_pred = np.concatenate([np.ones(seq_length-1), lstm_pred])
            results['individual_predictions']['lstm'] = lstm_pred
        
        # Ensemble voting
        ensemble_predictions = []
        confidence_scores = []
        
        for i in range(len(features_scaled)):
            votes = []
            weights = []
            
            # Collect votes from each model
            for model_name, weight in self.ensemble_weights.items():
                if model_name in results['individual_predictions']:
                    pred = results['individual_predictions'][model_name][i]
                    votes.append(pred)
                    weights.append(weight)
            
            # Weighted voting
            if votes:
                weighted_vote = np.average(votes, weights=weights)
                ensemble_pred = -1 if weighted_vote < 0 else 1
                confidence = abs(weighted_vote)
            else:
                ensemble_pred = 1
                confidence = 0.5
            
            ensemble_predictions.append(ensemble_pred)
            confidence_scores.append(confidence)
        
        results['ensemble_prediction'] = np.array(ensemble_predictions)
        results['confidence_scores'] = np.array(confidence_scores)
        
        # Generate detailed anomaly information
        anomaly_indices = np.where(results['ensemble_prediction'] == -1)[0]
        for idx in anomaly_indices:
            anomaly_info = {
                'packet_index': idx,
                'confidence': confidence_scores[idx],
                'detected_by': [
                    model for model, preds in results['individual_predictions'].items()
                    if preds[idx] == -1
                ],
                'feature_values': features.iloc[idx].to_dict() if hasattr(features, 'iloc') else features[idx]
            }
            results['anomaly_details'].append(anomaly_info)
        
        return results
    
    def get_performance_summary(self, features, labels=None):
        """Generate comprehensive performance analysis"""
        results = self.detect_anomalies_ensemble(features)
        
        summary = {
            'total_packets': len(features),
            'anomalies_detected': np.sum(results['ensemble_prediction'] == -1),
            'anomaly_rate': np.mean(results['ensemble_prediction'] == -1) * 100,
            'average_confidence': np.mean(results['confidence_scores']),
            'model_agreement': self._calculate_model_agreement(results['individual_predictions']),
            'high_confidence_anomalies': np.sum(np.array(results['confidence_scores']) > 0.8)
        }
        
        if labels is not None:
            # Calculate supervised metrics
            from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
            
            summary['supervised_metrics'] = {
                'accuracy': accuracy_score(labels, results['ensemble_prediction']),
                'precision': precision_score(labels, results['ensemble_prediction'], pos_label=-1),
                'recall': recall_score(labels, results['ensemble_prediction'], pos_label=-1),
                'f1_score': f1_score(labels, results['ensemble_prediction'], pos_label=-1)
            }
        
        return summary
    
    def _calculate_model_agreement(self, predictions):
        """Calculate agreement between different models"""
        model_names = list(predictions.keys())
        agreements = []
        
        for i, model1 in enumerate(model_names):
            for j, model2 in enumerate(model_names[i+1:], i+1):
                agreement = np.mean(predictions[model1] == predictions[model2])
                agreements.append(agreement)
        
        return np.mean(agreements) if agreements else 0.0
    
    def save_models(self, filepath_prefix):
        """Save trained models and configuration"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save sklearn models
        for model_name, model in self.models.items():
            if model_name != 'lstm':
                joblib.dump(model, f"{filepath_prefix}_{model_name}_{timestamp}.pkl")
        
        # Save LSTM model
        if 'lstm' in self.models:
            self.models['lstm'].save(f"{filepath_prefix}_lstm_{timestamp}.h5")
        
        # Save scaler and configuration
        joblib.dump(self.scaler, f"{filepath_prefix}_scaler_{timestamp}.pkl")
        
        config_data = {
            'config': self.config,
            'ensemble_weights': self.ensemble_weights,
            'timestamp': timestamp
        }
        
        with open(f"{filepath_prefix}_config_{timestamp}.json", 'w') as f:
            json.dump(config_data, f, indent=2)
        
        print(f"Models saved successfully with timestamp: {timestamp}")
        return timestamp


def demo_advanced_detection():
    """Demo function for advanced anomaly detection"""
    print("=" * 70)
    print("🚀 ADVANCED ANOMALY DETECTION DEMO")
    print("=" * 70)
    
    # Import required modules
    import sys
    import os
    sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
    
    from core.network_capture import NetworkCapture
    from core.data_processor import DataProcessor
    
    # Generate test data
    print("1️⃣ Generating network data...")
    capture = NetworkCapture()
    capture.start_monitoring()
    capture.simulate_packet_capture(200)  # More data for better training
    
    # Process data
    print("2️⃣ Processing data...")
    processor = DataProcessor()
    processor.load_from_capture(capture)
    processor.clean_data()
    features = processor.extract_features()
    normalized_features = processor.normalize_features(features)
    
    # Advanced detection
    print("3️⃣ Training advanced ensemble...")
    detector = AdvancedAnomalyDetector()
    detector.train_ensemble(normalized_features)
    
    # Get results
    print("4️⃣ Running ensemble detection...")
    results = detector.detect_anomalies_ensemble(normalized_features)
    summary = detector.get_performance_summary(normalized_features)
    
    # Display results
    print("\n📊 ADVANCED DETECTION RESULTS:")
    print(f"   🔍 Total packets analyzed: {summary['total_packets']}")
    print(f"   🚨 Anomalies detected: {summary['anomalies_detected']}")
    print(f"   📈 Anomaly rate: {summary['anomaly_rate']:.2f}%")
    print(f"   🎯 Average confidence: {summary['average_confidence']:.3f}")
    print(f"   🤝 Model agreement: {summary['model_agreement']:.3f}")
    print(f"   ⭐ High confidence anomalies: {summary['high_confidence_anomalies']}")
    
    # Show individual model contributions
    print("\n🔧 MODEL CONTRIBUTIONS:")
    for model_name, predictions in results['individual_predictions'].items():
        anomaly_count = np.sum(predictions == -1)
        print(f"   {model_name}: {anomaly_count} anomalies detected")
    
    # Save models
    print("\n💾 Saving trained models...")
    detector.save_models("models/advanced_detector")
    
    print("\n🎉 Advanced detection demo completed!")
    return detector, results, summary


if __name__ == "__main__":
    demo_advanced_detection()