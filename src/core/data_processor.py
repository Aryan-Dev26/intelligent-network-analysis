"""
Network Data Processing Module
Author: [Aryan Pravin Sahu]
Description: Processes raw network data for ML analysis and visualization
"""

import json
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import List, Dict, Any, Tuple
import re
import os


class DataProcessor:
    """
    Advanced network data processing for ML pipeline
    Transforms raw packet data into ML-ready features
    """
    
    def __init__(self):
        self.raw_data = []
        self.processed_data = None
        self.features = []
        self.scaler_params = {}
        
    def load_from_json(self, filename: str) -> bool:
        """Load network capture data from JSON file"""
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
                self.raw_data = data.get('packets', [])
                print(f"✅ Loaded {len(self.raw_data)} packets from {filename}")
                return True
        except Exception as e:
            print(f"❌ Error loading data: {e}")
            return False
            
    def load_from_capture(self, network_capture_instance):
        """Load data directly from NetworkCapture instance"""
        self.raw_data = network_capture_instance.captured_packets
        print(f"✅ Loaded {len(self.raw_data)} packets from capture instance")
        
    def clean_data(self) -> pd.DataFrame:
        """Clean and standardize raw network data"""
        print("🧹 Cleaning network data...")
        
        if not self.raw_data:
            print("❌ No data to clean!")
            return pd.DataFrame()
            
        # Convert to DataFrame
        df = pd.DataFrame(self.raw_data)
        
        print(f"   📊 Original data shape: {df.shape}")
        
        # Data cleaning steps
        initial_count = len(df)
        
        # 1. Remove duplicates
        df = df.drop_duplicates()
        print(f"   🗑️ Removed {initial_count - len(df)} duplicate packets")
        
        # 2. Handle missing values
        df = df.dropna()
        
        # 3. Standardize IP addresses (remove invalid ones)
        df = self._validate_ips(df)
        
        # 4. Normalize timestamps
        df = self._process_timestamps(df)
        
        # 5. Clean protocol names
        df['protocol'] = df['protocol'].str.upper()
        
        # 6. Validate port ranges
        df = df[(df['src_port'] >= 1) & (df['src_port'] <= 65535)]
        df = df[(df['dst_port'] >= 1) & (df['dst_port'] <= 65535)]
        
        print(f"   ✅ Cleaned data shape: {df.shape}")
        self.processed_data = df
        return df
        
    def _validate_ips(self, df: pd.DataFrame) -> pd.DataFrame:
        """Validate and clean IP addresses"""
        ip_pattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        
        # Remove invalid IPs
        valid_src = df['src_ip'].str.match(ip_pattern, na=False)
        valid_dst = df['dst_ip'].str.match(ip_pattern, na=False)
        
        before_count = len(df)
        df = df[valid_src & valid_dst]
        removed = before_count - len(df)
        
        if removed > 0:
            print(f"   🔍 Removed {removed} packets with invalid IP addresses")
            
        return df
        
    def _process_timestamps(self, df: pd.DataFrame) -> pd.DataFrame:
        """Process and normalize timestamps"""
        # Convert timestamp strings to datetime
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Add time-based features
        df['hour'] = df['timestamp'].dt.hour
        df['day_of_week'] = df['timestamp'].dt.dayofweek
        df['is_weekend'] = df['day_of_week'].isin([5, 6])
        
        # Calculate time differences (flow duration approximation)
        df = df.sort_values('timestamp')
        df['time_delta'] = df['timestamp'].diff().dt.total_seconds().fillna(0)
        
        return df
        
    def extract_features(self) -> pd.DataFrame:
        """Extract ML-ready features from processed data"""
        print("🔧 Extracting features for ML...")
        
        if self.processed_data is None:
            print("❌ No processed data available. Run clean_data() first.")
            return pd.DataFrame()
            
        df = self.processed_data.copy()
        
        # Feature Engineering
        features_df = pd.DataFrame()
        
        # 1. Basic packet features
        features_df['packet_size'] = df['size']
        features_df['src_port'] = df['src_port']
        features_df['dst_port'] = df['dst_port']
        
        # 2. Protocol encoding (one-hot)
        protocol_dummies = pd.get_dummies(df['protocol'], prefix='protocol')
        features_df = pd.concat([features_df, protocol_dummies], axis=1)
        
        # 3. Time-based features
        features_df['hour'] = df['hour']
        features_df['day_of_week'] = df['day_of_week']
        features_df['is_weekend'] = df['is_weekend'].astype(int)
        features_df['time_delta'] = df['time_delta']
        
        # 4. IP-based features
        features_df['is_internal_src'] = df['src_ip'].str.startswith('192.168.').astype(int)
        features_df['is_internal_dst'] = df['dst_ip'].str.startswith('192.168.').astype(int)
        features_df['same_subnet'] = (features_df['is_internal_src'] == features_df['is_internal_dst']).astype(int)
        
        # 5. Port classification
        features_df['is_well_known_port'] = (df['dst_port'] < 1024).astype(int)
        features_df['is_ephemeral_port'] = (df['src_port'] > 32767).astype(int)
        
        # 6. Suspicious indicators
        features_df['large_packet'] = (df['size'] > 1400).astype(int)
        features_df['is_suspicious'] = df['is_suspicious'].astype(int)
        
        # 7. Statistical features (rolling windows)
        features_df['size_rolling_mean'] = df['size'].rolling(window=10, min_periods=1).mean()
        features_df['size_rolling_std'] = df['size'].rolling(window=10, min_periods=1).std().fillna(0)
        
        # 8. Flag-based features
        features_df['num_flags'] = df['flags'].str.count(',') + 1
        features_df['has_syn'] = df['flags'].str.contains('SYN', na=False).astype(int)
        features_df['has_ack'] = df['flags'].str.contains('ACK', na=False).astype(int)
        features_df['has_rst'] = df['flags'].str.contains('RST', na=False).astype(int)
        
        print(f"   ✅ Extracted {features_df.shape[1]} features from {features_df.shape[0]} packets")
        
        self.features = features_df
        return features_df
        
    def normalize_features(self, features_df: pd.DataFrame = None) -> pd.DataFrame:
        """Normalize features for ML algorithms"""
        if features_df is None:
            features_df = self.features
            
        if features_df.empty:
            print("❌ No features to normalize!")
            return pd.DataFrame()
            
        print("📏 Normalizing features...")
        
        # Separate numerical and categorical features
        numerical_cols = features_df.select_dtypes(include=[np.number]).columns
        categorical_cols = features_df.select_dtypes(exclude=[np.number]).columns
        
        # Normalize numerical features (Min-Max scaling)
        normalized_df = features_df.copy()
        
        for col in numerical_cols:
            min_val = features_df[col].min()
            max_val = features_df[col].max()
            
            # Store scaling parameters
            self.scaler_params[col] = {'min': min_val, 'max': max_val}
            
            # Apply min-max scaling
            if max_val != min_val:  # Avoid division by zero
                normalized_df[col] = (features_df[col] - min_val) / (max_val - min_val)
            else:
                normalized_df[col] = 0
                
        print(f"   ✅ Normalized {len(numerical_cols)} numerical features")
        
        return normalized_df
        
    def get_data_summary(self) -> Dict[str, Any]:
        """Get comprehensive summary of processed data"""
        if self.processed_data is None:
            return {"error": "No processed data available"}
            
        df = self.processed_data
        
        return {
            'data_info': {
                'total_packets': len(df),
                'time_range': f"{df['timestamp'].min()} to {df['timestamp'].max()}",
                'duration_hours': (df['timestamp'].max() - df['timestamp'].min()).total_seconds() / 3600
            },
            'traffic_stats': {
                'total_bytes': df['size'].sum(),
                'avg_packet_size': df['size'].mean(),
                'max_packet_size': df['size'].max(),
                'min_packet_size': df['size'].min()
            },
            'protocol_distribution': df['protocol'].value_counts().to_dict(),
            'suspicious_packets': {
                'count': df['is_suspicious'].sum(),
                'percentage': (df['is_suspicious'].sum() / len(df)) * 100
            },
            'network_analysis': {
                'internal_traffic': df['src_ip'].str.startswith('192.168.').sum(),
                'external_traffic': (~df['src_ip'].str.startswith('192.168.')).sum(),
                'unique_src_ips': df['src_ip'].nunique(),
                'unique_dst_ips': df['dst_ip'].nunique()
            },
            'time_analysis': {
                'peak_hour': df.groupby('hour').size().idxmax(),
                'weekend_traffic': df['is_weekend'].sum(),
                'weekday_traffic': (~df['is_weekend']).sum()
            }
        }
        
    def save_processed_data(self, filename: str = None):
        """Save processed data and features"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"data/processed/processed_network_data_{timestamp}.csv"
            
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        
        if self.processed_data is not None:
            # Save processed data
            self.processed_data.to_csv(filename, index=False)
            
            # Save features if available
            if not self.features.empty:
                features_filename = filename.replace('.csv', '_features.csv')
                self.features.to_csv(features_filename, index=False)
                print(f"💾 Features saved to: {features_filename}")
                
            # Save summary
            summary_filename = filename.replace('.csv', '_summary.json')
            summary = self.get_data_summary()
            with open(summary_filename, 'w') as f:
                json.dump(summary, f, indent=2, default=str)
                
            print(f"💾 Processed data saved to: {filename}")
            print(f"💾 Summary saved to: {summary_filename}")
            
            return filename
        else:
            print("❌ No processed data to save!")
            return None


def demo_data_processing():
    """
    Demo function showing data processing pipeline
    """
    print("=" * 60)
    print("🔧 DATA PROCESSING PIPELINE DEMO")
    print("=" * 60)
    
    # First, generate some sample data using our network capture
    print("1️⃣ Generating sample network data...")
    from network_capture import NetworkCapture
    
    capture = NetworkCapture()
    capture.start_monitoring()
    capture.simulate_packet_capture(100)  # Generate 100 packets
    
    # Now process the data
    print("\n2️⃣ Processing the captured data...")
    processor = DataProcessor()
    processor.load_from_capture(capture)
    
    # Clean the data
    print("\n3️⃣ Cleaning data...")
    cleaned_data = processor.clean_data()
    
    # Extract features
    print("\n4️⃣ Extracting ML features...")
    features = processor.extract_features()
    
    # Normalize features
    print("\n5️⃣ Normalizing features...")
    normalized_features = processor.normalize_features()
    
    # Get summary
    print("\n6️⃣ Data summary:")
    summary = processor.get_data_summary()
    
    print(f"   📊 Total packets processed: {summary['data_info']['total_packets']}")
    print(f"   📦 Average packet size: {summary['traffic_stats']['avg_packet_size']:.2f} bytes")
    print(f"   🚨 Suspicious packets: {summary['suspicious_packets']['count']} ({summary['suspicious_packets']['percentage']:.1f}%)")
    print(f"   🌐 Unique source IPs: {summary['network_analysis']['unique_src_ips']}")
    print(f"   ⏰ Peak traffic hour: {summary['time_analysis']['peak_hour']}:00")
    
    print(f"\n   🔧 Features extracted: {len(features.columns)} features")
    print(f"   📏 Feature names: {list(features.columns[:10])}... (showing first 10)")
    
    # Save processed data
    print("\n7️⃣ Saving processed data...")
    filename = processor.save_processed_data()
    
    print("\n🎉 Data processing pipeline complete!")
    print("✅ Your data is now ML-ready!")
    
    return processor, features, normalized_features


if __name__ == "__main__":
    demo_data_processing()