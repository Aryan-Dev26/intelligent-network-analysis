"""
Real-time Network Stream Processing System
Implements sliding window analysis and adaptive learning
Author: Aryan Pravin Sahu
Research Focus: Real-time cybersecurity for IoT networks
"""

import numpy as np
import pandas as pd
from collections import deque
import threading
import time
from datetime import datetime, timedelta
import queue
import json
from typing import Dict, List, Callable, Optional

class StreamProcessor:
    """
    Real-time network stream processor with adaptive learning
    Designed for continuous monitoring and dynamic threat detection
    """
    
    def __init__(self, window_size=100, update_interval=10):
        self.window_size = window_size
        self.update_interval = update_interval
        self.packet_buffer = deque(maxlen=window_size)
        self.feature_buffer = deque(maxlen=window_size)
        self.anomaly_buffer = deque(maxlen=1000)
        
        # Threading components
        self.processing_queue = queue.Queue()
        self.is_running = False
        self.processor_thread = None
        
        # Adaptive learning components
        self.baseline_stats = {}
        self.drift_detector = ConceptDriftDetector()
        self.alert_system = AlertSystem()
        
        # Performance metrics
        self.metrics = {
            'packets_processed': 0,
            'anomalies_detected': 0,
            'processing_time': [],
            'false_positive_rate': 0.0,
            'detection_latency': []
        }
        
        # Callbacks for real-time alerts
        self.alert_callbacks = []
    
    def add_alert_callback(self, callback: Callable):
        """Add callback function for real-time alerts"""
        self.alert_callbacks.append(callback)
    
    def start_processing(self):
        """Start real-time stream processing"""
        if self.is_running:
            print("⚠️ Stream processor already running!")
            return
        
        self.is_running = True
        self.processor_thread = threading.Thread(target=self._processing_loop)
        self.processor_thread.daemon = True
        self.processor_thread.start()
        
        print("🚀 Real-time stream processing started!")
    
    def stop_processing(self):
        """Stop stream processing"""
        self.is_running = False
        if self.processor_thread:
            self.processor_thread.join()
        print("⏹️ Stream processing stopped!")
    
    def ingest_packet(self, packet_data: Dict):
        """Ingest new packet for real-time processing"""
        timestamp = datetime.now()
        packet_data['ingestion_timestamp'] = timestamp
        
        # Add to processing queue
        self.processing_queue.put(packet_data)
        
        # Update buffer
        self.packet_buffer.append(packet_data)
    
    def _processing_loop(self):
        """Main processing loop running in separate thread"""
        while self.is_running:
            try:
                # Process packets in batches for efficiency
                batch = []
                batch_start = time.time()
                
                # Collect batch of packets
                while len(batch) < 10 and not self.processing_queue.empty():
                    try:
                        packet = self.processing_queue.get_nowait()
                        batch.append(packet)
                    except queue.Empty:
                        break
                
                if batch:
                    self._process_batch(batch)
                    
                    # Update metrics
                    processing_time = time.time() - batch_start
                    self.metrics['processing_time'].append(processing_time)
                    self.metrics['packets_processed'] += len(batch)
                
                # Sleep briefly to prevent CPU overload
                time.sleep(0.1)
                
            except Exception as e:
                print(f"❌ Error in processing loop: {e}")
    
    def _process_batch(self, batch: List[Dict]):
        """Process a batch of packets"""
        # Extract features from batch
        features = self._extract_batch_features(batch)
        
        # Detect anomalies
        anomalies = self._detect_batch_anomalies(features)
        
        # Update adaptive learning
        self._update_baseline_stats(features)
        
        # Check for concept drift
        drift_detected = self.drift_detector.check_drift(features)
        if drift_detected:
            self._handle_concept_drift()
        
        # Process alerts
        for i, is_anomaly in enumerate(anomalies):
            if is_anomaly:
                self._handle_anomaly_alert(batch[i], features[i])
    
    def _extract_batch_features(self, batch: List[Dict]) -> np.ndarray:
        """Extract features from packet batch"""
        features = []
        
        for packet in batch:
            # Basic packet features
            feature_vector = [
                packet.get('size', 0),
                packet.get('src_port', 0),
                packet.get('dst_port', 0),
                self._encode_protocol(packet.get('protocol', 'TCP')),
                self._extract_time_features(packet.get('timestamp')),
                self._calculate_flow_features(packet),
                self._detect_suspicious_patterns(packet)
            ]
            
            # Flatten nested features
            flat_features = []
            for item in feature_vector:
                if isinstance(item, (list, tuple)):
                    flat_features.extend(item)
                else:
                    flat_features.append(item)
            
            features.append(flat_features)
        
        return np.array(features)
    
    def _encode_protocol(self, protocol: str) -> List[float]:
        """One-hot encode protocol"""
        protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'FTP']
        encoding = [1.0 if protocol.upper() == p else 0.0 for p in protocols]
        return encoding
    
    def _extract_time_features(self, timestamp) -> List[float]:
        """Extract time-based features"""
        if timestamp is None:
            timestamp = datetime.now()
        elif isinstance(timestamp, str):
            # Convert ISO string to datetime object
            timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        
        return [
            float(timestamp.hour),
            float(timestamp.weekday()),
            float(timestamp.weekday() >= 5),  # is_weekend
            float((timestamp.hour >= 22) or (timestamp.hour <= 6))  # is_night
        ]
    
    def _calculate_flow_features(self, packet: Dict) -> List[float]:
        """Calculate flow-based features using sliding window"""
        src_ip = packet.get('src_ip', '')
        dst_ip = packet.get('dst_ip', '')
        
        # Count recent packets from same source
        recent_packets = list(self.packet_buffer)[-50:]  # Last 50 packets
        
        src_count = sum(1 for p in recent_packets if p.get('src_ip') == src_ip)
        dst_count = sum(1 for p in recent_packets if p.get('dst_ip') == dst_ip)
        
        # Calculate flow statistics
        same_flow_packets = [
            p for p in recent_packets 
            if p.get('src_ip') == src_ip and p.get('dst_ip') == dst_ip
        ]
        
        flow_rate = len(same_flow_packets) / max(1, len(recent_packets))
        avg_size = np.mean([p.get('size', 0) for p in same_flow_packets]) if same_flow_packets else 0
        
        return [float(src_count), float(dst_count), flow_rate, avg_size]
    
    def _detect_suspicious_patterns(self, packet: Dict) -> List[float]:
        """Detect suspicious patterns in packet"""
        suspicious_indicators = []
        
        # Large packet size
        suspicious_indicators.append(float(packet.get('size', 0) > 1400))
        
        # Unusual port combinations
        src_port = packet.get('src_port', 0)
        dst_port = packet.get('dst_port', 0)
        suspicious_indicators.append(float(src_port > 50000 and dst_port < 1024))
        
        # Rapid succession (if timestamps available)
        if len(self.packet_buffer) > 1:
            last_packet = self.packet_buffer[-1]
            time_diff = 0
            if 'timestamp' in packet and 'timestamp' in last_packet:
                try:
                    # Convert string timestamps to datetime objects
                    current_time = packet['timestamp']
                    last_time = last_packet['timestamp']
                    
                    if isinstance(current_time, str):
                        current_time = datetime.fromisoformat(current_time.replace('Z', '+00:00'))
                    if isinstance(last_time, str):
                        last_time = datetime.fromisoformat(last_time.replace('Z', '+00:00'))
                    
                    time_diff = (current_time - last_time).total_seconds()
                except (ValueError, TypeError):
                    time_diff = 0
            suspicious_indicators.append(float(time_diff < 0.001))  # Very rapid
        else:
            suspicious_indicators.append(0.0)
        
        return suspicious_indicators
    
    def _detect_batch_anomalies(self, features: np.ndarray) -> List[bool]:
        """Detect anomalies in feature batch using statistical methods"""
        anomalies = []
        
        for feature_vector in features:
            # Z-score based detection
            if self.baseline_stats:
                z_scores = []
                for i, value in enumerate(feature_vector):
                    if i in self.baseline_stats:
                        mean = self.baseline_stats[i]['mean']
                        std = self.baseline_stats[i]['std']
                        if std > 0:
                            z_score = abs((value - mean) / std)
                            z_scores.append(z_score)
                
                # Anomaly if any feature has z-score > 3
                is_anomaly = any(z > 3.0 for z in z_scores) if z_scores else False
            else:
                # Initial packets - use simple thresholds
                is_anomaly = any(abs(x) > 10 for x in feature_vector)
            
            anomalies.append(is_anomaly)
        
        return anomalies
    
    def _update_baseline_stats(self, features: np.ndarray):
        """Update baseline statistics for adaptive learning"""
        for feature_vector in features:
            for i, value in enumerate(feature_vector):
                if i not in self.baseline_stats:
                    self.baseline_stats[i] = {
                        'mean': value,
                        'std': 0.0,
                        'count': 1,
                        'sum': value,
                        'sum_sq': value * value
                    }
                else:
                    stats = self.baseline_stats[i]
                    stats['count'] += 1
                    stats['sum'] += value
                    stats['sum_sq'] += value * value
                    
                    # Update running mean and std
                    stats['mean'] = stats['sum'] / stats['count']
                    variance = (stats['sum_sq'] / stats['count']) - (stats['mean'] ** 2)
                    stats['std'] = np.sqrt(max(0, variance))
    
    def _handle_concept_drift(self):
        """Handle detected concept drift"""
        print("🔄 Concept drift detected - adapting model...")
        
        # Reset baseline statistics with decay
        for feature_idx in self.baseline_stats:
            stats = self.baseline_stats[feature_idx]
            stats['count'] = max(1, stats['count'] * 0.5)  # Decay factor
        
        # Trigger model retraining if using ML models
        self.alert_system.add_alert({
            'type': 'concept_drift',
            'timestamp': datetime.now(),
            'message': 'Network behavior pattern change detected'
        })
    
    def _handle_anomaly_alert(self, packet: Dict, features: np.ndarray):
        """Handle anomaly detection alert"""
        alert = {
            'type': 'anomaly',
            'timestamp': datetime.now(),
            'packet': packet,
            'features': features.tolist(),
            'severity': self._calculate_severity(features),
            'description': self._generate_anomaly_description(packet, features)
        }
        
        # Add to anomaly buffer
        self.anomaly_buffer.append(alert)
        self.metrics['anomalies_detected'] += 1
        
        # Trigger callbacks
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                print(f"❌ Error in alert callback: {e}")
        
        # Add to alert system
        self.alert_system.add_alert(alert)
    
    def _calculate_severity(self, features: np.ndarray) -> str:
        """Calculate anomaly severity based on feature deviation"""
        if not self.baseline_stats:
            return 'medium'
        
        max_z_score = 0
        for i, value in enumerate(features):
            if i in self.baseline_stats:
                stats = self.baseline_stats[i]
                if stats['std'] > 0:
                    z_score = abs((value - stats['mean']) / stats['std'])
                    max_z_score = max(max_z_score, z_score)
        
        if max_z_score > 5:
            return 'high'
        elif max_z_score > 3:
            return 'medium'
        else:
            return 'low'
    
    def _generate_anomaly_description(self, packet: Dict, features: np.ndarray) -> str:
        """Generate human-readable anomaly description"""
        descriptions = []
        
        # Check specific anomaly types
        if packet.get('size', 0) > 1400:
            descriptions.append("Unusually large packet size")
        
        if packet.get('src_port', 0) > 50000 and packet.get('dst_port', 0) < 1024:
            descriptions.append("Suspicious port combination")
        
        # Add more specific checks based on features
        if len(descriptions) == 0:
            descriptions.append("Statistical anomaly detected")
        
        return "; ".join(descriptions)
    
    def get_real_time_metrics(self) -> Dict:
        """Get current performance metrics"""
        current_time = datetime.now()
        
        # Calculate recent anomaly rate (last 5 minutes)
        recent_anomalies = [
            a for a in self.anomaly_buffer 
            if (current_time - a['timestamp']).total_seconds() < 300
        ]
        
        return {
            'packets_processed': self.metrics['packets_processed'],
            'total_anomalies': self.metrics['anomalies_detected'],
            'recent_anomaly_rate': len(recent_anomalies) / max(1, len(self.packet_buffer)) * 100,
            'avg_processing_time': np.mean(self.metrics['processing_time'][-100:]) if self.metrics['processing_time'] else 0,
            'buffer_utilization': len(self.packet_buffer) / self.window_size * 100,
            'drift_status': self.drift_detector.get_status(),
            'active_alerts': len(self.alert_system.get_active_alerts())
        }


class ConceptDriftDetector:
    """Detect concept drift in network traffic patterns"""
    
    def __init__(self, window_size=1000, threshold=0.1):
        self.window_size = window_size
        self.threshold = threshold
        self.reference_window = deque(maxlen=window_size)
        self.current_window = deque(maxlen=window_size)
        self.drift_detected = False
        
    def check_drift(self, features: np.ndarray) -> bool:
        """Check for concept drift using statistical tests"""
        # Add features to current window
        for feature_vector in features:
            self.current_window.append(feature_vector)
        
        # Need sufficient data for comparison
        if len(self.reference_window) < self.window_size // 2:
            # Build reference window
            for feature_vector in features:
                self.reference_window.append(feature_vector)
            return False
        
        if len(self.current_window) < self.window_size // 2:
            return False
        
        # Perform drift detection using Kolmogorov-Smirnov test
        drift_score = self._calculate_drift_score()
        
        if drift_score > self.threshold:
            self.drift_detected = True
            # Update reference window
            self.reference_window = deque(list(self.current_window), maxlen=self.window_size)
            self.current_window.clear()
            return True
        
        return False
    
    def _calculate_drift_score(self) -> float:
        """Calculate drift score between reference and current windows"""
        ref_data = np.array(list(self.reference_window))
        cur_data = np.array(list(self.current_window))
        
        # Simple statistical comparison (mean difference)
        ref_mean = np.mean(ref_data, axis=0)
        cur_mean = np.mean(cur_data, axis=0)
        
        # Normalized difference
        diff = np.abs(ref_mean - cur_mean)
        ref_std = np.std(ref_data, axis=0)
        
        # Avoid division by zero
        normalized_diff = np.divide(diff, ref_std, out=np.zeros_like(diff), where=ref_std!=0)
        
        return np.mean(normalized_diff)
    
    def get_status(self) -> Dict:
        """Get drift detector status"""
        return {
            'drift_detected': self.drift_detected,
            'reference_samples': len(self.reference_window),
            'current_samples': len(self.current_window)
        }


class AlertSystem:
    """Manage and prioritize security alerts"""
    
    def __init__(self, max_alerts=1000):
        self.alerts = deque(maxlen=max_alerts)
        self.active_alerts = []
        
    def add_alert(self, alert: Dict):
        """Add new alert to system"""
        alert['id'] = len(self.alerts)
        alert['status'] = 'active'
        
        self.alerts.append(alert)
        self.active_alerts.append(alert)
        
        # Auto-resolve old alerts
        self._cleanup_old_alerts()
    
    def _cleanup_old_alerts(self):
        """Remove old alerts automatically"""
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(hours=1)
        
        self.active_alerts = [
            alert for alert in self.active_alerts
            if alert['timestamp'] > cutoff_time
        ]
    
    def get_active_alerts(self) -> List[Dict]:
        """Get currently active alerts"""
        self._cleanup_old_alerts()
        return self.active_alerts
    
    def get_alert_summary(self) -> Dict:
        """Get summary of alert statistics"""
        active = self.get_active_alerts()
        
        severity_counts = {}
        type_counts = {}
        
        for alert in active:
            severity = alert.get('severity', 'unknown')
            alert_type = alert.get('type', 'unknown')
            
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            type_counts[alert_type] = type_counts.get(alert_type, 0) + 1
        
        return {
            'total_active': len(active),
            'by_severity': severity_counts,
            'by_type': type_counts,
            'latest_alert': active[-1]['timestamp'] if active else None
        }


def demo_stream_processing():
    """Demo real-time stream processing"""
    print("=" * 70)
    print("🌊 REAL-TIME STREAM PROCESSING DEMO")
    print("=" * 70)
    
    # Create stream processor
    processor = StreamProcessor(window_size=50, update_interval=5)
    
    # Add alert callback
    def alert_callback(alert):
        print(f"🚨 ALERT: {alert['type']} - {alert.get('description', 'No description')}")
    
    processor.add_alert_callback(alert_callback)
    
    # Start processing
    processor.start_processing()
    
    # Simulate real-time packet ingestion
    print("📡 Simulating real-time packet stream...")
    
    import sys
    import os
    sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
    
    from core.network_capture import NetworkCapture
    
    # Generate packets in real-time
    capture = NetworkCapture()
    capture.start_monitoring()
    
    try:
        for i in range(100):
            # Generate a packet
            # Generate a single packet using the existing method
            single_packet_batch = capture.simulate_packet_capture(1)
            if single_packet_batch:
                packet = single_packet_batch[0]
            else:
                continue
            
            # Ingest into stream processor
            processor.ingest_packet(packet)
            
            # Print metrics every 20 packets
            if i % 20 == 0:
                metrics = processor.get_real_time_metrics()
                print(f"📊 Processed: {metrics['packets_processed']}, "
                      f"Anomalies: {metrics['total_anomalies']}, "
                      f"Recent Rate: {metrics['recent_anomaly_rate']:.1f}%")
            
            # Small delay to simulate real-time
            time.sleep(0.1)
    
    except KeyboardInterrupt:
        print("\n⏹️ Stopping demo...")
    
    finally:
        processor.stop_processing()
        
        # Final metrics
        final_metrics = processor.get_real_time_metrics()
        print("\n📈 FINAL METRICS:")
        print(f"   Total packets processed: {final_metrics['packets_processed']}")
        print(f"   Total anomalies detected: {final_metrics['total_anomalies']}")
        print(f"   Average processing time: {final_metrics['avg_processing_time']:.4f}s")
        print(f"   Buffer utilization: {final_metrics['buffer_utilization']:.1f}%")
        
        # Alert summary
        alert_summary = processor.alert_system.get_alert_summary()
        print(f"\n🚨 ALERT SUMMARY:")
        print(f"   Active alerts: {alert_summary['total_active']}")
        print(f"   By severity: {alert_summary['by_severity']}")
        print(f"   By type: {alert_summary['by_type']}")
    
    print("\n🎉 Stream processing demo completed!")


if __name__ == "__main__":
    demo_stream_processing()