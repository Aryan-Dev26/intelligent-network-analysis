#!/usr/bin/env python3
"""
Test the new detailed anomaly tracking feature
"""

import sys
import os
sys.path.append('src')

from core.real_network_capture import RealNetworkCapture
import json

def test_anomaly_tracking():
    """Test the detailed anomaly tracking functionality"""
    
    print("🧪 Testing Detailed Anomaly Tracking")
    print("=" * 50)
    
    # Initialize capture
    capture = RealNetworkCapture()
    
    # Create test packets that should trigger anomalies
    test_packets = [
        {
            'id': 1,
            'timestamp': '2024-01-01T12:00:00',
            'src_ip': '192.168.1.100',
            'dst_ip': '10.0.0.1',
            'src_port': 54321,
            'dst_port': 4444,  # Known malicious port
            'protocol': 'TCP',
            'transport': 'TCP',
            'flags': 'SYN',
            'size': 60,
            'is_suspicious': True,
            'risk_indicators': ['known_malicious_port']
        },
        {
            'id': 2,
            'timestamp': '2024-01-01T12:00:01',
            'src_ip': '192.168.1.100',
            'dst_ip': '10.0.0.1',
            'src_port': 54322,
            'dst_port': 22,
            'protocol': 'TCP',
            'transport': 'TCP',
            'flags': 'FIN,SYN',  # Stealth scan
            'size': 40,
            'is_suspicious': True,
            'risk_indicators': ['stealth_scan_attempt']
        },
        {
            'id': 3,
            'timestamp': '2024-01-01T12:00:02',
            'src_ip': '192.168.1.100',
            'dst_ip': '8.8.8.8',
            'src_port': 54323,
            'dst_port': 443,  # Normal HTTPS
            'protocol': 'TCP',
            'transport': 'TCP',
            'flags': 'SYN,ACK',
            'size': 1460,
            'is_suspicious': False,
            'risk_indicators': []
        }
    ]
    
    print("1. Testing anomaly detection and logging...")
    
    # Process test packets
    for packet in test_packets:
        if packet['is_suspicious']:
            capture._log_detailed_anomaly(packet)
            print(f"   ✓ Logged anomaly for packet {packet['id']}")
    
    print(f"\n2. Anomaly tracking results:")
    print(f"   Total anomalies detected: {capture.anomaly_count}")
    print(f"   Anomalies stored: {len(capture.anomaly_details)}")
    
    # Test getting anomaly details
    print("\n3. Testing anomaly retrieval...")
    recent_anomalies = capture.get_recent_anomalies(5)
    print(f"   Recent anomalies retrieved: {len(recent_anomalies)}")
    
    # Display detailed information
    print("\n4. Detailed anomaly information:")
    for i, anomaly in enumerate(recent_anomalies, 1):
        print(f"\n   Anomaly #{i}:")
        print(f"     ID: {anomaly.get('anomaly_id')}")
        print(f"     Threat Category: {anomaly.get('risk_analysis', {}).get('threat_category')}")
        print(f"     Connection: {anomaly.get('packet_info', {}).get('src_ip')}:{anomaly.get('packet_info', {}).get('src_port')} → {anomaly.get('packet_info', {}).get('dst_ip')}:{anomaly.get('packet_info', {}).get('dst_port')}")
        print(f"     Process: {anomaly.get('process_info', {}).get('name')} (PID: {anomaly.get('process_info', {}).get('pid')})")
        print(f"     Explanation: {anomaly.get('explanation')}")
    
    # Test summary generation
    print("\n5. Testing anomaly summary...")
    summary = capture._generate_anomaly_summary()
    print(f"   Summary generated: {json.dumps(summary, indent=2)}")
    
    # Test export functionality
    print("\n6. Testing anomaly report export...")
    try:
        filename = capture.export_anomaly_report()
        print(f"   ✓ Report exported to: {filename}")
        
        # Verify the file was created
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                report_data = json.load(f)
            print(f"   ✓ Report contains {len(report_data.get('detailed_anomalies', []))} anomalies")
        else:
            print(f"   ❌ Report file not found: {filename}")
            
    except Exception as e:
        print(f"   ❌ Export failed: {e}")
    
    print("\n" + "=" * 50)
    print("✅ Anomaly tracking test completed!")
    print("\nKey features tested:")
    print("• Detailed anomaly logging with process information")
    print("• Risk categorization and explanation generation")
    print("• Anomaly summary and statistics")
    print("• Export functionality for detailed reports")
    print("\nThis will help you understand exactly what's causing")
    print("the port scan alerts in your network monitoring system.")

if __name__ == "__main__":
    test_anomaly_tracking()