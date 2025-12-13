"""
Advanced Research Dashboard for Network Anomaly Detection
Research-grade Flask application with ensemble ML and real-time processing
Author: Aryan Pravin Sahu
"""

from flask import Flask, render_template, jsonify, request
import sys
import os
import json
import threading
import time
import numpy as np
from datetime import datetime

sys.path.append(os.path.join(os.path.dirname(__file__),'..'))

from core.network_capture import NetworkCapture
from core.data_processor import DataProcessor
from core.anomaly_detector import BasicAnomalyDetector
from ml.advanced_detector import AdvancedAnomalyDetector
from core.stream_processor import StreamProcessor
from ai.threat_intelligence import ThreatIntelligenceEngine
from ai.explainable_ai import ExplainableAI
from core.real_network_capture import RealNetworkCapture
from security.security_config import SecurityConfig, setup_secure_environment

app = Flask(__name__)

# Global variables for real-time processing
stream_processor = None
advanced_detector = None
threat_intelligence = None
explainable_ai = None
real_network_capture = None
security_config = None
is_processing = False
is_real_monitoring = False

# Initialize AI components
threat_intelligence = ThreatIntelligenceEngine()
explainable_ai = ExplainableAI()

# Initialize security configuration
security_config = SecurityConfig()

@app.route('/')
def dashboard():
    """Main research dashboard with advanced analytics"""
    return render_template('research_dashboard.html')

@app.route('/api/basic_analysis')
def basic_analysis():
    """Basic anomaly detection analysis"""
    try:
        print("🔍 Running basic analysis...")
        
        # Generate data
        capture = NetworkCapture()
        capture.start_monitoring()
        capture.simulate_packet_capture(100)
        
        # Process data
        processor = DataProcessor()
        processor.load_from_capture(capture)
        processor.clean_data()
        features = processor.extract_features()
        
        # Basic detection
        detector = BasicAnomalyDetector()
        detector.train(features)
        results = detector.detect_anomalies(features)
        
        return jsonify({
            'status': 'success',
            'analysis_type': 'basic',
            'results': {
                'total_packets': int(results['total_packets']),
                'anomalies_found': int(results['anomalies_found']),
                'anomaly_rate': float(results['anomaly_rate'])
            },
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/advanced_analysis')
def advanced_analysis():
    """Advanced ensemble anomaly detection"""
    try:
        print("🚀 Running advanced ensemble analysis...")
        
        # Generate more data for better training
        capture = NetworkCapture()
        capture.start_monitoring()
        capture.simulate_packet_capture(200)
        
        # Process data
        processor = DataProcessor()
        processor.load_from_capture(capture)
        processor.clean_data()
        features = processor.extract_features()
        normalized_features = processor.normalize_features(features)
        
        # Advanced ensemble detection
        global advanced_detector
        advanced_detector = AdvancedAnomalyDetector()
        advanced_detector.train_ensemble(normalized_features)
        
        # Get detailed results
        ensemble_results = advanced_detector.detect_anomalies_ensemble(normalized_features)
        performance_summary = advanced_detector.get_performance_summary(normalized_features)
        
        # Prepare response data with proper type conversion
        response_data = {
            'status': 'success',
            'analysis_type': 'advanced_ensemble',
            'performance_summary': {
                'total_packets': int(performance_summary['total_packets']),
                'anomalies_detected': int(performance_summary['anomalies_detected']),
                'anomaly_rate': float(performance_summary['anomaly_rate']),
                'average_confidence': float(performance_summary['average_confidence']),
                'model_agreement': float(performance_summary['model_agreement']),
                'high_confidence_anomalies': int(performance_summary['high_confidence_anomalies'])
            },
            'individual_models': {
                model: int(sum(preds == -1)) 
                for model, preds in ensemble_results['individual_predictions'].items()
            },
            'ensemble_results': {
                'total_anomalies': int(sum(ensemble_results['ensemble_prediction'] == -1)),
                'average_confidence': float(ensemble_results['confidence_scores'].mean()),
                'high_confidence_count': int(sum(ensemble_results['confidence_scores'] > 0.8))
            },
            'anomaly_details': [
                {
                    'packet_index': int(detail['packet_index']),
                    'confidence': float(detail['confidence']),
                    'detected_by': detail['detected_by']
                }
                for detail in ensemble_results['anomaly_details'][:10]
            ],
            'timestamp': datetime.now().isoformat()
        }
        
        return jsonify(response_data)
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/start_realtime')
def start_realtime():
    """Start real-time stream processing"""
    global stream_processor, is_processing
    
    try:
        if is_processing:
            return jsonify({
                'status': 'warning',
                'message': 'Real-time processing already running'
            })
        
        print("🌊 Starting real-time stream processing...")
        
        # Initialize stream processor
        stream_processor = StreamProcessor(window_size=50, update_interval=5)
        
        # Add alert callback for web notifications
        def web_alert_callback(alert):
            print(f"🚨 Web Alert: {alert['type']} - {alert.get('description', '')}")
        
        stream_processor.add_alert_callback(web_alert_callback)
        
        # Start processing
        stream_processor.start_processing()
        is_processing = True
        
        # Start packet simulation in background
        def simulate_packets():
            capture = NetworkCapture()
            capture.start_monitoring()
            
            for i in range(500):  # Simulate 500 packets
                if not is_processing:
                    break
                
                # Generate a single packet using the existing method
                single_packet_batch = capture.simulate_packet_capture(1)
                if single_packet_batch:
                    packet = single_packet_batch[0]
                    stream_processor.ingest_packet(packet)
                time.sleep(0.2)  # 5 packets per second
        
        packet_thread = threading.Thread(target=simulate_packets)
        packet_thread.daemon = True
        packet_thread.start()
        
        return jsonify({
            'status': 'success',
            'message': 'Real-time processing started',
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/stop_realtime')
def stop_realtime():
    """Stop real-time stream processing"""
    global stream_processor, is_processing
    
    try:
        if not is_processing:
            return jsonify({
                'status': 'warning',
                'message': 'Real-time processing not running'
            })
        
        print("⏹️ Stopping real-time processing...")
        
        is_processing = False
        if stream_processor:
            stream_processor.stop_processing()
        
        return jsonify({
            'status': 'success',
            'message': 'Real-time processing stopped',
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/realtime_metrics')
def realtime_metrics():
    """Get current real-time processing metrics"""
    global stream_processor, is_processing
    
    try:
        if not is_processing or not stream_processor:
            return jsonify({
                'status': 'inactive',
                'message': 'Real-time processing not active'
            })
        
        metrics = stream_processor.get_real_time_metrics()
        alert_summary = stream_processor.alert_system.get_alert_summary()
        
        return jsonify({
            'status': 'active',
            'metrics': metrics,
            'alerts': alert_summary,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/ai_threat_analysis')
def ai_threat_analysis():
    """AI-powered threat intelligence analysis"""
    try:
        print("Running AI threat intelligence analysis...")
        
        # Generate sample data for analysis
        capture = NetworkCapture()
        capture.start_monitoring()
        capture.simulate_packet_capture(50)
        
        # Process data
        processor = DataProcessor()
        processor.load_from_capture(capture)
        processor.clean_data()
        features = processor.extract_features()
        
        # Run basic anomaly detection
        detector = BasicAnomalyDetector()
        detector.train(features)
        results = detector.detect_anomalies(features)
        
        # Find anomalous packets for AI analysis
        anomalous_packets = []
        if results['anomalies_found'] > 0:
            # Look for actual attack packets first, then anomalous ones
            attack_packets = [p for p in capture.captured_packets if p.get('attack_type')]
            suspicious_packets = [p for p in capture.captured_packets if p.get('is_suspicious')]
            
            # Combine attack packets and suspicious packets
            packets_to_analyze = attack_packets + suspicious_packets
            
            for i, packet_data in enumerate(packets_to_analyze[:3]):  # Analyze top 3
                # Simulate anomaly data
                anomaly_data = {
                    'confidence': 0.95 if packet_data.get('attack_type') else 0.75,
                    'detected_by': ['isolation_forest', 'ensemble'] if packet_data.get('attack_type') else ['isolation_forest'],
                    'packet_index': i
                }
                
                # Run AI threat intelligence
                threat_analysis = threat_intelligence.analyze_threat_intelligence(
                    anomaly_data, packet_data
                )
                
                anomalous_packets.append({
                    'packet_index': i,
                    'packet_data': packet_data,
                    'threat_analysis': {
                        'risk_score': threat_analysis['risk_score'],
                        'threat_type': threat_analysis['threat_classification']['primary_type'],
                        'confidence': threat_analysis['confidence_level'],
                        'recommendations': threat_analysis['recommendations'][:2]  # Top 2 recommendations
                    }
                })
        
        return jsonify({
            'status': 'success',
            'analysis_type': 'ai_threat_intelligence',
            'total_packets': results['total_packets'],
            'anomalies_analyzed': len(anomalous_packets),
            'threat_analysis': anomalous_packets,
            'summary': {
                'avg_risk_score': float(np.mean([p['threat_analysis']['risk_score'] for p in anomalous_packets])) if anomalous_packets else 0,
                'threat_types': list(set([p['threat_analysis']['threat_type'] for p in anomalous_packets])),
                'high_risk_count': sum(1 for p in anomalous_packets if p['threat_analysis']['risk_score'] > 70)
            },
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/explain_anomaly')
def explain_anomaly():
    """Generate explainable AI analysis for anomaly detection"""
    try:
        print("Generating explainable AI analysis...")
        
        # Generate sample data
        capture = NetworkCapture()
        capture.start_monitoring()
        capture.simulate_packet_capture(20)
        
        # Process data
        processor = DataProcessor()
        processor.load_from_capture(capture)
        processor.clean_data()
        features = processor.extract_features()
        normalized_features = processor.normalize_features(features)
        
        # Run advanced detection for more detailed results
        global advanced_detector
        if not advanced_detector:
            advanced_detector = AdvancedAnomalyDetector()
            advanced_detector.train_ensemble(normalized_features)
        
        # Get ensemble results
        ensemble_results = advanced_detector.detect_anomalies_ensemble(normalized_features)
        
        # Find first anomaly for explanation
        anomaly_indices = np.where(ensemble_results['ensemble_prediction'] == -1)[0]
        
        if len(anomaly_indices) > 0:
            anomaly_idx = anomaly_indices[0]
            
            # Get feature values for this specific anomaly
            feature_values = normalized_features.iloc[anomaly_idx].values
            feature_names = list(normalized_features.columns)
            
            # Generate explanation
            explanation = explainable_ai.explain_anomaly_decision(
                ensemble_results, feature_values, feature_names, 'ensemble'
            )
            
            # Generate formatted report
            explanation_report = explainable_ai.generate_explanation_report(explanation)
            
            # Convert numpy types to Python types for JSON serialization
            top_features_json = []
            for feature in explanation['feature_analysis']['top_contributing_features'][:5]:
                top_features_json.append({
                    'name': feature['name'],
                    'contribution': {
                        'value': float(feature['contribution']['value']),
                        'contribution_score': float(feature['contribution']['contribution_score']),
                        'is_unusual': bool(feature['contribution']['is_unusual']),
                        'description': feature['contribution']['description']
                    },
                    'score': float(feature['score'])
                })
            
            counterfactuals_json = []
            for cf in explanation['counterfactual_analysis']['suggestions'][:3]:
                counterfactuals_json.append({
                    'feature': cf['feature'],
                    'current_value': float(cf['current_value']),
                    'suggested_normal_value': float(cf['suggested_normal_value']),
                    'explanation': cf['explanation']
                })
            
            return jsonify({
                'status': 'success',
                'analysis_type': 'explainable_ai',
                'anomaly_index': int(anomaly_idx),
                'explanation': {
                    'summary': explanation['natural_language']['summary'],
                    'confidence': explanation['explanation_confidence']['level'],
                    'top_features': top_features_json,
                    'counterfactuals': counterfactuals_json,
                    'technical_summary': explanation['natural_language']['technical_summary']
                },
                'detailed_report': explanation_report,
                'visual_data': explanation['visual_explanation'],
                'timestamp': datetime.now().isoformat()
            })
        else:
            return jsonify({
                'status': 'success',
                'analysis_type': 'explainable_ai',
                'message': 'No anomalies detected in current sample',
                'timestamp': datetime.now().isoformat()
            })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/research_summary')
def research_summary():
    """Get comprehensive research summary"""
    try:
        # Read research methodology
        methodology_path = os.path.join(
            os.path.dirname(__file__), 
            '..', '..', 'docs', 'research', 'research_methodology.md'
        )
        
        methodology_content = ""
        if os.path.exists(methodology_path):
            with open(methodology_path, 'r', encoding='utf-8') as f:
                methodology_content = f.read()
        
        # System capabilities summary
        capabilities = {
            'algorithms': [
                'Isolation Forest (Unsupervised)',
                'DBSCAN Clustering',
                'One-Class SVM',
                'LSTM Autoencoder (Deep Learning)'
            ],
            'features': [
                'Real-time Stream Processing',
                'Concept Drift Detection',
                'Ensemble Learning',
                'Adaptive Thresholds',
                'Multi-level Alerting'
            ],
            'metrics': [
                'Detection Accuracy',
                'Processing Latency',
                'False Positive Rate',
                'Throughput (packets/sec)',
                'Memory Efficiency'
            ],
            'research_focus': [
                'IoT Network Security',
                'Real-time Threat Detection',
                'Adaptive Machine Learning',
                'Ensemble Methods',
                'Edge Computing Security'
            ]
        }
        
        return jsonify({
            'status': 'success',
            'capabilities': capabilities,
            'methodology_available': bool(methodology_content),
            'methodology_preview': methodology_content[:500] + "..." if methodology_content else "",
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/attack_simulation')
def attack_simulation():
    """Generate network traffic with specific attack simulations"""
    try:
        print("Running attack simulation analysis...")
        
        # Generate data with attacks
        capture = NetworkCapture()
        capture.start_monitoring()
        packets = capture.simulate_packet_capture(100, include_attacks=True)
        
        # Analyze attack distribution
        attack_stats = {}
        normal_count = 0
        
        for packet in packets:
            attack_type = packet.get('attack_type')
            if attack_type:
                attack_stats[attack_type] = attack_stats.get(attack_type, 0) + 1
            else:
                normal_count += 1
        
        # Get detailed attack information
        attack_details = []
        for packet in packets:
            if packet.get('attack_type'):
                attack_details.append({
                    'packet_id': packet['id'],
                    'attack_type': packet['attack_type'],
                    'description': packet.get('attack_description', ''),
                    'src_ip': packet['src_ip'],
                    'dst_ip': packet['dst_ip'],
                    'dst_port': packet['dst_port'],
                    'size': packet['size'],
                    'protocol': packet['protocol']
                })
        
        return jsonify({
            'status': 'success',
            'analysis_type': 'attack_simulation',
            'total_packets': len(packets),
            'normal_packets': normal_count,
            'attack_packets': len(attack_details),
            'attack_distribution': attack_stats,
            'attack_details': attack_details[:10],  # Show first 10 attacks
            'simulation_summary': {
                'port_scans': attack_stats.get('port_scan', 0),
                'ddos_attacks': attack_stats.get('ddos', 0),
                'data_exfiltration': attack_stats.get('data_exfiltration', 0),
                'malware_beacons': attack_stats.get('malware_beacon', 0)
            },
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/security_status')
def security_status():
    """Get current security configuration and status"""
    try:
        global security_config
        
        if not security_config:
            security_config = SecurityConfig()
        
        # Get security report
        security_report = security_config.create_security_report()
        
        # Get capture limits
        capture_limits = security_config.get_capture_limits()
        
        return jsonify({
            'status': 'success',
            'security_report': security_report,
            'capture_limits': capture_limits,
            'real_monitoring_active': is_real_monitoring,
            'privacy_settings': {
                'anonymize_ips': security_config.should_anonymize_data(),
                'capture_payload': security_config.should_capture_payload(),
                'data_retention_days': security_config.get_data_retention_days()
            },
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/start_real_monitoring', methods=['POST'])
def start_real_monitoring():
    """Start real network traffic monitoring with security controls"""
    global real_network_capture, is_real_monitoring, security_config
    
    try:
        if is_real_monitoring:
            return jsonify({
                'status': 'warning',
                'message': 'Real network monitoring already active'
            })
        
        # Initialize security if not done
        if not security_config:
            security_config = SecurityConfig()
        
        # Get user consent (this would normally be done through UI)
        # For API, we assume consent is given through the request
        request_data = request.get_json() or {}
        consent_given = request_data.get('consent_granted', False)
        
        if not consent_given:
            return jsonify({
                'status': 'error',
                'message': 'User consent required for real network monitoring',
                'consent_required': True
            }), 400
        
        # Get monitoring parameters
        interface = request_data.get('interface', None)
        duration = request_data.get('duration', 300)  # Default 5 minutes
        
        # Get capture limits first
        limits = security_config.get_capture_limits()
        
        # Initialize real network capture with security settings
        real_network_capture = RealNetworkCapture(interface=interface)
        
        # Apply security settings
        real_network_capture.anonymize_ips = security_config.should_anonymize_data()
        real_network_capture.capture_payload = security_config.should_capture_payload()
        
        # Recreate the captured_packets deque with new maxlen
        from collections import deque
        real_network_capture.captured_packets = deque(maxlen=limits['max_packets_per_session'])
        
        # Try to start monitoring, fall back to simulation if needed
        success = real_network_capture.start_monitoring(duration=duration)
        
        if success:
            is_real_monitoring = True
            return jsonify({
                'status': 'success',
                'message': 'Real network monitoring started',
                'monitoring_duration': duration,
                'security_settings': {
                    'anonymize_ips': real_network_capture.anonymize_ips,
                    'capture_payload': real_network_capture.capture_payload,
                    'max_packets': limits['max_packets_per_session']
                },
                'timestamp': datetime.now().isoformat()
            })
        else:
            # Fall back to enhanced simulation mode for demonstration
            print("Real packet capture not available, starting enhanced simulation mode...")
            
            # Start enhanced simulation that mimics real monitoring
            def simulate_real_monitoring():
                from core.network_capture import NetworkCapture
                sim_capture = NetworkCapture()
                sim_capture.start_monitoring()
                
                # Generate realistic network traffic over time
                for batch in range(10):  # 10 batches over time
                    if not is_real_monitoring:
                        break
                    
                    # Generate batch of packets with realistic timing
                    packets = sim_capture.simulate_packet_capture(20, include_attacks=True)
                    
                    # Add to real_network_capture for consistency
                    for packet in packets:
                        # Simulate security processing
                        if real_network_capture.anonymize_ips:
                            packet['src_ip'] = real_network_capture._anonymize_ip(packet['src_ip'])
                            packet['dst_ip'] = real_network_capture._anonymize_ip(packet['dst_ip'])
                        
                        # Add security analysis
                        packet['is_suspicious'] = packet.get('attack_type') is not None
                        packet['risk_indicators'] = []
                        if packet.get('attack_type'):
                            packet['risk_indicators'].append(f"{packet['attack_type']}_detected")
                        
                        real_network_capture.captured_packets.append(packet)
                        real_network_capture.packet_count += 1
                    
                    time.sleep(2)  # Realistic timing between batches
            
            # Start simulation in background
            sim_thread = threading.Thread(target=simulate_real_monitoring)
            sim_thread.daemon = True
            sim_thread.start()
            
            is_real_monitoring = True
            return jsonify({
                'status': 'success',
                'message': 'Enhanced simulation mode started (demonstration mode)',
                'monitoring_duration': duration,
                'mode': 'simulation',
                'security_settings': {
                    'anonymize_ips': real_network_capture.anonymize_ips,
                    'capture_payload': real_network_capture.capture_payload,
                    'max_packets': limits['max_packets_per_session']
                },
                'note': 'Using enhanced simulation for demonstration purposes',
                'timestamp': datetime.now().isoformat()
            })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/stop_real_monitoring')
def stop_real_monitoring():
    """Stop real network traffic monitoring"""
    global real_network_capture, is_real_monitoring
    
    try:
        if not is_real_monitoring:
            return jsonify({
                'status': 'warning',
                'message': 'Real network monitoring not active'
            })
        
        if real_network_capture:
            real_network_capture.stop_monitoring()
        
        is_real_monitoring = False
        
        return jsonify({
            'status': 'success',
            'message': 'Real network monitoring stopped',
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/real_monitoring_stats')
def real_monitoring_stats():
    """Get real network monitoring statistics"""
    global real_network_capture, is_real_monitoring
    
    try:
        if not is_real_monitoring or not real_network_capture:
            return jsonify({
                'status': 'inactive',
                'message': 'Real network monitoring not active'
            })
        
        # Get capture statistics
        stats = real_network_capture.get_capture_statistics()
        
        # Get recent packets for analysis
        recent_packets = list(real_network_capture.captured_packets)[-10:]  # Last 10 packets
        
        # Analyze for security threats
        security_analysis = {
            'suspicious_packets': sum(1 for p in recent_packets if p.get('is_suspicious', False)),
            'risk_indicators': {},
            'port_analysis': {},
            'protocol_distribution': {}
        }
        
        # Analyze risk indicators
        all_indicators = []
        for packet in recent_packets:
            indicators = packet.get('risk_indicators', [])
            all_indicators.extend(indicators)
        
        for indicator in set(all_indicators):
            security_analysis['risk_indicators'][indicator] = all_indicators.count(indicator)
        
        # Port and protocol analysis
        for packet in recent_packets:
            port = packet.get('dst_port', 0)
            protocol = packet.get('protocol', 'unknown')
            
            if port:
                security_analysis['port_analysis'][str(port)] = security_analysis['port_analysis'].get(str(port), 0) + 1
            
            security_analysis['protocol_distribution'][protocol] = security_analysis['protocol_distribution'].get(protocol, 0) + 1
        
        return jsonify({
            'status': 'active',
            'capture_stats': stats,
            'security_analysis': security_analysis,
            'recent_packets': recent_packets,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/network_interfaces')
def network_interfaces():
    """Get available network interfaces for monitoring"""
    try:
        import psutil
        
        interfaces = []
        for interface_name, interface_addresses in psutil.net_if_addrs().items():
            interface_info = {
                'name': interface_name,
                'addresses': []
            }
            
            for address in interface_addresses:
                if address.family.name in ['AF_INET', 'AF_INET6']:
                    interface_info['addresses'].append({
                        'family': address.family.name,
                        'address': address.address,
                        'netmask': getattr(address, 'netmask', None)
                    })
            
            if interface_info['addresses']:  # Only include interfaces with IP addresses
                interfaces.append(interface_info)
        
        return jsonify({
            'status': 'success',
            'interfaces': interfaces,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/export_real_data')
def export_real_data():
    """Export captured real network data"""
    global real_network_capture
    
    try:
        if not real_network_capture:
            return jsonify({
                'status': 'error',
                'message': 'No real network capture session available'
            }), 400
        
        # Export packets to file
        filename = real_network_capture.export_packets()
        
        return jsonify({
            'status': 'success',
            'message': 'Real network data exported',
            'filename': filename,
            'packet_count': len(real_network_capture.captured_packets),
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/research')
def research_page():
    """Research methodology and documentation page"""
    return render_template('research_methodology.html')

if __name__ == '__main__':
    print("Starting Advanced Research Dashboard with Real Network Monitoring...")
    print("Main Dashboard: http://localhost:5000")
    print("Research Page: http://localhost:5000/research")
    print("Real Network Monitoring with Security Controls Available")
    print("AI-powered API Endpoints available for analysis")
    app.run(debug=True, threaded=True)