#!/usr/bin/env python3
"""
Inject anomalies directly into the running web application
This connects to the running system and injects test data
"""

import requests
import json
import time
from datetime import datetime

def check_monitoring_status():
    """Check if the web application monitoring is running"""
    try:
        response = requests.get('http://localhost:5000/api/real_monitoring_stats', timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"Monitoring Status: {data.get('status', 'unknown')}")
            return data.get('status') == 'active'
        else:
            print(f"Error checking status: {response.status_code}")
            return False
    except Exception as e:
        print(f"Cannot connect to web application: {e}")
        return False

def start_monitoring_if_needed():
    """Start monitoring if it's not already running"""
    try:
        # Try to start monitoring
        response = requests.post('http://localhost:5000/api/start_real_monitoring', 
                               json={'duration': 300, 'interface': None}, 
                               timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            print(f"Monitoring start result: {data.get('message', 'Unknown')}")
            return data.get('status') == 'success'
        else:
            print(f"Failed to start monitoring: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"Error starting monitoring: {e}")
        return False

def create_test_packets_via_api():
    """Create test packets by making the system capture them"""
    print("🔍 Creating network activity that the running system will detect...")
    
    # Import socket to create real network activity
    import socket
    import threading
    
    def create_malicious_connections():
        """Create connections to malicious ports"""
        malicious_ports = [4444, 5555, 6666, 1337, 31337]
        
        for port in malicious_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('localhost', port))
                sock.close()
                print(f"   → Attempted connection to malicious port {port}")
                time.sleep(0.5)
            except Exception as e:
                print(f"   → Port {port}: {e}")
    
    def create_port_scan():
        """Create rapid port scanning"""
        scan_ports = [21, 22, 23, 80, 135, 139, 443, 445, 3389]
        
        for port in scan_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                result = sock.connect_ex(('127.0.0.1', port))
                sock.close()
                time.sleep(0.05)  # Rapid scanning
            except Exception:
                pass
        
        print("   → Performed rapid port scan")
    
    def create_large_udp_packets():
        """Create large UDP packets"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            large_payload = b'SUSPICIOUS_DATA_' * 100  # Large packet
            
            for port in [1337, 4444, 5555]:
                try:
                    sock.sendto(large_payload, ('127.0.0.1', port))
                    print(f"   → Sent large UDP packet to port {port}")
                    time.sleep(0.3)
                except Exception as e:
                    print(f"   → UDP to port {port}: {e}")
            
            sock.close()
        except Exception as e:
            print(f"   → UDP error: {e}")
    
    # Run all activities
    print("\n1. Creating malicious port connections...")
    create_malicious_connections()
    
    print("\n2. Performing port scan...")
    create_port_scan()
    
    print("\n3. Creating large UDP packets...")
    create_large_udp_packets()
    
    print("\n✅ Network activity generated!")
    print("The running monitoring system should detect this activity.")

def wait_and_check_results():
    """Wait for the system to process the activity and check results"""
    print("\n⏳ Waiting for system to process the network activity...")
    
    for i in range(10):  # Wait up to 30 seconds
        time.sleep(3)
        
        try:
            # Check monitoring stats
            response = requests.get('http://localhost:5000/api/real_monitoring_stats', timeout=5)
            if response.status_code == 200:
                data = response.json()
                
                if data.get('status') == 'active':
                    security = data.get('security_analysis', {})
                    suspicious_count = security.get('suspicious_packets', 0)
                    
                    print(f"   Check {i+1}: Suspicious packets detected: {suspicious_count}")
                    
                    if suspicious_count > 0:
                        print("✅ Anomalies detected by the running system!")
                        
                        # Show risk indicators
                        risk_indicators = security.get('risk_indicators', {})
                        if risk_indicators:
                            print(f"   Risk indicators: {risk_indicators}")
                        
                        return True
                else:
                    print(f"   Check {i+1}: Monitoring not active")
            else:
                print(f"   Check {i+1}: API error {response.status_code}")
                
        except Exception as e:
            print(f"   Check {i+1}: Error - {e}")
    
    print("⚠️  No anomalies detected yet. The system might need more time or different activity.")
    return False

def check_anomaly_details():
    """Check the detailed anomaly information"""
    try:
        response = requests.get('http://localhost:5000/api/anomaly_details', timeout=5)
        if response.status_code == 200:
            data = response.json()
            
            total_anomalies = data.get('total_anomalies', 0)
            recent_anomalies = data.get('recent_anomalies', [])
            
            print(f"\n📊 Anomaly Details:")
            print(f"   Total anomalies: {total_anomalies}")
            print(f"   Recent anomalies: {len(recent_anomalies)}")
            
            if recent_anomalies:
                print("\n🚨 Recent Anomaly Details:")
                for i, anomaly in enumerate(recent_anomalies[-3:], 1):  # Show last 3
                    packet = anomaly.get('packet_info', {})
                    risk = anomaly.get('risk_analysis', {})
                    
                    print(f"   {i}. {risk.get('threat_category', 'Unknown')} - {packet.get('src_ip')}:{packet.get('src_port')} → {packet.get('dst_ip')}:{packet.get('dst_port')}")
                    print(f"      Explanation: {anomaly.get('explanation', 'No explanation')}")
            
            return total_anomalies > 0
        else:
            print(f"Error getting anomaly details: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"Error checking anomaly details: {e}")
        return False

def force_ui_refresh():
    """Try to force the UI to refresh by making API calls"""
    print("\n🔄 Attempting to refresh UI state...")
    
    try:
        # Make multiple API calls to trigger UI updates
        endpoints = [
            '/api/real_monitoring_stats',
            '/api/anomaly_details'
        ]
        
        for endpoint in endpoints:
            response = requests.get(f'http://localhost:5000{endpoint}', timeout=5)
            print(f"   Refreshed {endpoint}: {response.status_code}")
            
        print("✅ UI refresh attempted. Try refreshing your browser page.")
        
    except Exception as e:
        print(f"Error refreshing UI: {e}")

def main():
    print("🔗 Inject Anomalies to Running System")
    print("=" * 50)
    print("This tool creates network activity that your running")
    print("web application should detect and display.")
    print()
    
    # Step 1: Check if monitoring is running
    print("1. Checking monitoring status...")
    if not check_monitoring_status():
        print("   Monitoring not active. Attempting to start...")
        if not start_monitoring_if_needed():
            print("❌ Could not start monitoring. Make sure the web app is running.")
            return
        
        # Wait a moment for monitoring to start
        time.sleep(3)
    
    print("✅ Monitoring is active")
    
    # Step 2: Create network activity
    print("\n2. Creating suspicious network activity...")
    create_test_packets_via_api()
    
    # Step 3: Wait and check results
    print("\n3. Checking for detection results...")
    detected = wait_and_check_results()
    
    # Step 4: Check detailed anomaly information
    print("\n4. Checking detailed anomaly information...")
    has_details = check_anomaly_details()
    
    # Step 5: Force UI refresh
    force_ui_refresh()
    
    # Summary
    print("\n" + "=" * 50)
    print("SUMMARY")
    print("=" * 50)
    
    if detected or has_details:
        print("✅ SUCCESS: Anomalies detected by the running system!")
        print("   Refresh your browser to see the updated dashboard.")
    else:
        print("⚠️  No anomalies detected yet.")
        print("   Possible reasons:")
        print("   • The detection algorithm is working correctly (no real threats)")
        print("   • The system needs administrator privileges for real packet capture")
        print("   • The UI needs to be refreshed")
        
    print("\n💡 Next steps:")
    print("1. Refresh your browser page")
    print("2. Check if 'Start Real Monitoring' button needs to be clicked")
    print("3. Look for any JavaScript errors in browser console (F12)")

if __name__ == "__main__":
    main()