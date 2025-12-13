#!/usr/bin/env python3
"""
Debug anomaly detection to understand why no anomalies are being detected
"""

import requests
import json
import sys
import os
sys.path.append('src')

from core.real_network_capture import RealNetworkCapture

def check_current_monitoring():
    """Check what the current monitoring system is detecting"""
    
    print("🔍 Debugging Anomaly Detection")
    print("=" * 50)
    
    # Check monitoring stats
    try:
        response = requests.get('http://localhost:5000/api/real_monitoring_stats', timeout=5)
        if response.status_code == 200:
            data = response.json()
            
            print("1. Current Monitoring Status:")
            if data.get('status') == 'active':
                stats = data.get('capture_stats', {})
                security = data.get('security_analysis', {})
                recent_packets = data.get('recent_packets', [])
                
                print(f"   Total Packets: {stats.get('total_packets', 0)}")
                print(f"   Suspicious Packets: {security.get('suspicious_packets', 0)}")
                print(f"   Recent Packets: {len(recent_packets)}")
                print(f"   Risk Indicators: {security.get('risk_indicators', {})}")
                
                # Analyze recent packets
                print("\n2. Recent Packet Analysis:")
                for i, packet in enumerate(recent_packets[-5:], 1):
                    print(f"   Packet {i}:")
                    print(f"     {packet.get('src_ip', 'unknown')}:{packet.get('src_port', '?')} → {packet.get('dst_ip', 'unknown')}:{packet.get('dst_port', '?')}")
                    print(f"     Protocol: {packet.get('protocol', 'unknown')}, Flags: {packet.get('flags', 'none')}")
                    print(f"     Suspicious: {packet.get('is_suspicious', False)}")
                    print(f"     Risk Indicators: {packet.get('risk_indicators', [])}")
                
                return recent_packets
            else:
                print("   Monitoring is not active")
                return []
        else:
            print(f"   Error: HTTP {response.status_code}")
            return []
            
    except Exception as e:
        print(f"   Error: {e}")
        return []

def test_detection_algorithm():
    """Test the detection algorithm with sample packets"""
    
    print("\n3. Testing Detection Algorithm:")
    
    # Create test packets based on what we saw before
    test_packets = [
        # Normal HTTPS (should NOT be suspicious)
        {
            'src_ip': '192.168.1.55', 'dst_ip': '40.74.79.222',
            'src_port': 54321, 'dst_port': 443,
            'protocol': 'TCP', 'transport': 'TCP',
            'flags': 'SYN,ACK', 'size': 1200
        },
        # Windows service (should NOT be suspicious)
        {
            'src_ip': '192.168.1.55', 'dst_ip': '52.123.253.131',
            'src_port': 61845, 'dst_port': 443,
            'protocol': 'TCP', 'transport': 'TCP',
            'flags': 'ACK', 'size': 800
        },
        # SYN to privileged port (might be suspicious in old algorithm)
        {
            'src_ip': '192.168.1.55', 'dst_ip': '10.0.0.1',
            'src_port': 54321, 'dst_port': 22,
            'protocol': 'TCP', 'transport': 'TCP',
            'flags': 'SYN', 'size': 60
        },
        # High port to low port (old algorithm flagged this)
        {
            'src_ip': '192.168.1.55', 'dst_ip': '10.0.0.1',
            'src_port': 55000, 'dst_port': 80,
            'protocol': 'TCP', 'transport': 'TCP',
            'flags': 'SYN', 'size': 60
        }
    ]
    
    capture = RealNetworkCapture()
    
    for i, packet in enumerate(test_packets, 1):
        is_suspicious = capture._analyze_packet_security(packet)
        risk_indicators = capture._get_risk_indicators(packet)
        
        print(f"\n   Test Packet {i}:")
        print(f"     Connection: {packet['src_ip']}:{packet['src_port']} → {packet['dst_ip']}:{packet['dst_port']}")
        print(f"     Flags: {packet['flags']}")
        print(f"     Suspicious: {is_suspicious}")
        print(f"     Risk Indicators: {risk_indicators}")
        
        if is_suspicious:
            print(f"     ✓ Would be flagged as anomaly")
        else:
            print(f"     ○ Would be considered normal")

def check_anomaly_api():
    """Check the anomaly details API"""
    
    print("\n4. Anomaly API Status:")
    try:
        response = requests.get('http://localhost:5000/api/anomaly_details', timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"   Total Anomalies: {data.get('total_anomalies', 0)}")
            print(f"   Recent Anomalies: {len(data.get('recent_anomalies', []))}")
            print(f"   Summary: {data.get('summary', {})}")
        else:
            print(f"   Error: HTTP {response.status_code}")
    except Exception as e:
        print(f"   Error: {e}")

def suggest_solutions():
    """Suggest solutions based on findings"""
    
    print("\n" + "=" * 50)
    print("ANALYSIS AND SOLUTIONS")
    print("=" * 50)
    
    print("\n🎯 Possible Reasons for 'No Anomalies Detected':")
    print("1. ✅ GOOD: The improved algorithm is working correctly")
    print("   - False positives have been eliminated")
    print("   - Your network traffic is actually legitimate")
    
    print("\n2. ⚠️  POSSIBLE: Algorithm is too strict now")
    print("   - Previous 'port scans' were actually normal traffic")
    print("   - Detection threshold might be too high")
    
    print("\n3. 🔄 TIMING: Fresh monitoring session")
    print("   - Anomaly counter resets when monitoring restarts")
    print("   - Need to wait for suspicious activity to occur")
    
    print("\n💡 What to do:")
    print("• If you want to see the old 'port scan' alerts:")
    print("  - Lower the detection threshold in the algorithm")
    print("  - Add back some of the broader detection rules")
    
    print("• If you prefer accurate detection (recommended):")
    print("  - Keep current algorithm")
    print("  - Monitor for real threats (malicious ports, stealth scans)")
    
    print("• To test the system:")
    print("  - Try connecting to suspicious ports (4444, 5555)")
    print("  - Use network scanning tools (if on your own network)")

def main():
    recent_packets = check_current_monitoring()
    test_detection_algorithm()
    check_anomaly_api()
    suggest_solutions()
    
    print(f"\n🔧 Quick Test:")
    print("To see if detection works, try this in another terminal:")
    print("telnet localhost 4444")
    print("(This should trigger a 'malicious port' detection)")

if __name__ == "__main__":
    main()