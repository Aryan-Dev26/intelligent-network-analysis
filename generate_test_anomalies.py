#!/usr/bin/env python3
"""
Generate Test Anomalies for Network Monitoring System
Creates safe, controlled network activity to test anomaly detection
"""

import socket
import time
import threading
import sys
import os
from datetime import datetime

def test_malicious_port_connection():
    """Test connection to known malicious ports"""
    print("🔍 Testing malicious port connections...")
    
    malicious_ports = [4444, 5555, 6666, 1337, 31337]
    
    for port in malicious_ports:
        try:
            print(f"   Attempting connection to localhost:{port}")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)  # 1 second timeout
            
            # This will fail but should be detected by monitoring
            result = sock.connect_ex(('localhost', port))
            sock.close()
            
            print(f"   → Connection to port {port}: {'Success' if result == 0 else 'Failed (expected)'}")
            time.sleep(0.5)  # Small delay between attempts
            
        except Exception as e:
            print(f"   → Port {port}: {e}")

def test_port_scanning_pattern():
    """Simulate port scanning behavior"""
    print("\n🔍 Testing port scanning pattern...")
    
    # Scan common service ports rapidly
    target_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 993, 995]
    
    for port in target_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)  # Very short timeout for scanning
            
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            
            print(f"   Scanning port {port}: {'Open' if result == 0 else 'Closed/Filtered'}")
            time.sleep(0.1)  # Rapid scanning
            
        except Exception as e:
            print(f"   Port {port}: {e}")

def test_suspicious_connections():
    """Test connections that should trigger anomaly detection"""
    print("\n🔍 Testing suspicious connection patterns...")
    
    suspicious_targets = [
        ('localhost', 4444, 'Backdoor port'),
        ('localhost', 5555, 'Personal agent port'),
        ('localhost', 6666, 'IRC/Trojan port'),
        ('127.0.0.1', 1234, 'Common backdoor'),
        ('127.0.0.1', 12345, 'NetBus trojan port'),
    ]
    
    for host, port, description in suspicious_targets:
        try:
            print(f"   Testing {description} ({host}:{port})")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            
            result = sock.connect_ex((host, port))
            sock.close()
            
            print(f"   → {description}: {'Connected' if result == 0 else 'Connection failed (expected)'}")
            time.sleep(0.3)
            
        except Exception as e:
            print(f"   → {description}: {e}")

def create_large_packets():
    """Generate unusually large network packets"""
    print("\n🔍 Testing oversized packet generation...")
    
    try:
        # Create a UDP socket for large packet test
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Create large payload (should trigger oversized packet detection)
        large_payload = b'A' * 2000  # 2KB payload
        
        print(f"   Sending oversized UDP packet ({len(large_payload)} bytes)")
        
        # Send to localhost (will fail but should be monitored)
        try:
            sock.sendto(large_payload, ('127.0.0.1', 9999))
            print("   → Large packet sent")
        except Exception as e:
            print(f"   → Large packet attempt: {e}")
        
        sock.close()
        
    except Exception as e:
        print(f"   → Large packet test error: {e}")

def simulate_stealth_scan():
    """Simulate stealth scanning techniques"""
    print("\n🔍 Testing stealth scan simulation...")
    
    # Note: We can't actually send packets with custom flags easily in Python
    # But we can simulate the connection patterns
    
    stealth_ports = [22, 80, 443, 3389]  # Common targets
    
    for port in stealth_ports:
        try:
            print(f"   Stealth probe to port {port}")
            
            # Multiple rapid connection attempts (SYN flood simulation)
            for i in range(3):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.05)  # Very short timeout
                
                result = sock.connect_ex(('127.0.0.1', port))
                sock.close()
                
                time.sleep(0.02)  # Very rapid attempts
            
            print(f"   → Stealth scan on port {port} completed")
            
        except Exception as e:
            print(f"   → Stealth scan error: {e}")

def run_continuous_anomaly_generation():
    """Run continuous anomaly generation for testing"""
    print("\n🔄 Starting continuous anomaly generation...")
    print("   This will generate suspicious activity every 10 seconds")
    print("   Press Ctrl+C to stop")
    
    try:
        cycle = 0
        while True:
            cycle += 1
            print(f"\n--- Anomaly Generation Cycle {cycle} ---")
            
            # Rotate through different types of suspicious activity
            if cycle % 4 == 1:
                test_malicious_port_connection()
            elif cycle % 4 == 2:
                test_port_scanning_pattern()
            elif cycle % 4 == 3:
                test_suspicious_connections()
            else:
                create_large_packets()
            
            print(f"   Waiting 10 seconds before next cycle...")
            time.sleep(10)
            
    except KeyboardInterrupt:
        print("\n\n🛑 Anomaly generation stopped by user")

def main():
    print("🧪 Network Anomaly Generation Tool")
    print("=" * 50)
    print("This tool generates safe, controlled network activity")
    print("that should trigger your anomaly detection system.")
    print()
    
    print("Available tests:")
    print("1. Single test run (all anomaly types once)")
    print("2. Continuous anomaly generation")
    print("3. Malicious port connections only")
    print("4. Port scanning simulation only")
    print("5. Exit")
    
    while True:
        try:
            choice = input("\nChoose an option (1-5): ").strip()
            
            if choice == '1':
                print("\n🚀 Running single test cycle...")
                test_malicious_port_connection()
                test_port_scanning_pattern()
                test_suspicious_connections()
                create_large_packets()
                simulate_stealth_scan()
                
                print("\n✅ Single test cycle completed!")
                print("Check your monitoring dashboard for detected anomalies.")
                
            elif choice == '2':
                run_continuous_anomaly_generation()
                
            elif choice == '3':
                test_malicious_port_connection()
                test_suspicious_connections()
                
            elif choice == '4':
                test_port_scanning_pattern()
                simulate_stealth_scan()
                
            elif choice == '5':
                print("👋 Exiting anomaly generator")
                break
                
            else:
                print("Invalid choice. Please enter 1-5.")
                
        except KeyboardInterrupt:
            print("\n\n👋 Exiting anomaly generator")
            break
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    main()