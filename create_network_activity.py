#!/usr/bin/env python3
"""
Create Real Network Activity for Testing
Generates actual network connections that should be detected
"""

import socket
import threading
import time
import subprocess
import sys
import os
from datetime import datetime

def test_malicious_ports():
    """Create connections to known malicious ports"""
    print("🔍 Creating connections to malicious ports...")
    
    malicious_ports = [4444, 5555, 6666, 1337, 31337, 12345]
    
    for port in malicious_ports:
        try:
            print(f"   Connecting to localhost:{port}")
            
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            
            # Attempt connection (will fail but should be monitored)
            try:
                sock.connect(('localhost', port))
                print(f"   ✓ Connected to port {port}")
                sock.close()
            except socket.error:
                print(f"   → Connection to port {port} failed (expected)")
            
            time.sleep(0.5)
            
        except Exception as e:
            print(f"   Error with port {port}: {e}")

def rapid_port_scan():
    """Perform rapid port scanning that should be detected"""
    print("\n🔍 Performing rapid port scan...")
    
    target_ports = [21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 993, 995, 3389]
    
    print(f"   Scanning {len(target_ports)} ports rapidly...")
    
    for port in target_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)  # Very short timeout
            
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            
            if result == 0:
                print(f"   ✓ Port {port} is open")
            
            time.sleep(0.05)  # Rapid scanning
            
        except Exception:
            pass  # Ignore errors for scanning

def create_suspicious_udp_traffic():
    """Create suspicious UDP traffic"""
    print("\n🔍 Creating suspicious UDP traffic...")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Send to suspicious ports
        suspicious_udp_ports = [1337, 4444, 5555, 31337]
        
        for port in suspicious_udp_ports:
            try:
                # Create large payload
                payload = b'SUSPICIOUS_DATA_' * 100  # ~1.5KB
                
                print(f"   Sending large UDP packet to port {port}")
                sock.sendto(payload, ('127.0.0.1', port))
                
                time.sleep(0.3)
                
            except Exception as e:
                print(f"   UDP to port {port}: {e}")
        
        sock.close()
        
    except Exception as e:
        print(f"   UDP traffic error: {e}")

def simulate_data_exfiltration():
    """Simulate data exfiltration patterns"""
    print("\n🔍 Simulating data exfiltration...")
    
    try:
        # Multiple connections to external-looking IPs (localhost for safety)
        exfil_ports = [5555, 6666, 8080, 9999]
        
        for port in exfil_ports:
            try:
                print(f"   Attempting data exfiltration to port {port}")
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                
                # Try to connect
                result = sock.connect_ex(('127.0.0.1', port))
                
                if result == 0:
                    # If connected, send large data
                    large_data = b'EXFILTRATED_DATA_' * 200  # ~3.4KB
                    sock.send(large_data)
                    print(f"   ✓ Data sent to port {port}")
                else:
                    print(f"   → Exfiltration attempt to port {port} (connection failed)")
                
                sock.close()
                time.sleep(0.5)
                
            except Exception as e:
                print(f"   Exfiltration to port {port}: {e}")
                
    except Exception as e:
        print(f"   Exfiltration simulation error: {e}")

def create_stealth_connections():
    """Create connections that might look like stealth scans"""
    print("\n🔍 Creating stealth-like connection patterns...")
    
    # Target common service ports with unusual patterns
    service_ports = [22, 80, 443, 3389, 5985]
    
    for port in service_ports:
        try:
            print(f"   Stealth probe to port {port}")
            
            # Multiple rapid connection attempts
            for attempt in range(3):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                
                result = sock.connect_ex(('127.0.0.1', port))
                sock.close()
                
                time.sleep(0.02)  # Very rapid
            
            time.sleep(0.2)
            
        except Exception as e:
            print(f"   Stealth probe error: {e}")

def run_nmap_scan():
    """Run an actual nmap scan if available"""
    print("\n🔍 Attempting nmap scan (if available)...")
    
    try:
        # Check if nmap is available
        result = subprocess.run(['nmap', '--version'], 
                              capture_output=True, text=True, timeout=5)
        
        if result.returncode == 0:
            print("   ✓ nmap found, running scan...")
            
            # Run a simple scan of localhost
            scan_result = subprocess.run([
                'nmap', '-sS', '-F', '127.0.0.1'
            ], capture_output=True, text=True, timeout=30)
            
            print("   ✓ nmap scan completed")
            print("   This should generate multiple suspicious connections")
            
        else:
            print("   → nmap not available, skipping")
            
    except subprocess.TimeoutExpired:
        print("   → nmap scan timed out")
    except FileNotFoundError:
        print("   → nmap not installed, skipping")
    except Exception as e:
        print(f"   → nmap error: {e}")

def continuous_suspicious_activity():
    """Generate continuous suspicious activity"""
    print("\n🔄 Starting continuous suspicious activity...")
    print("   This will generate suspicious network activity every 15 seconds")
    print("   Press Ctrl+C to stop")
    
    try:
        cycle = 0
        while True:
            cycle += 1
            print(f"\n--- Suspicious Activity Cycle {cycle} ({datetime.now().strftime('%H:%M:%S')}) ---")
            
            # Rotate through different activities
            if cycle % 5 == 1:
                test_malicious_ports()
            elif cycle % 5 == 2:
                rapid_port_scan()
            elif cycle % 5 == 3:
                create_suspicious_udp_traffic()
            elif cycle % 5 == 4:
                simulate_data_exfiltration()
            else:
                create_stealth_connections()
            
            print(f"   Waiting 15 seconds before next cycle...")
            time.sleep(15)
            
    except KeyboardInterrupt:
        print("\n\n🛑 Continuous activity stopped")

def main():
    print("🌐 Network Activity Generator")
    print("=" * 50)
    print("This tool creates real network connections that should")
    print("trigger your anomaly detection system.")
    print()
    print("⚠️  IMPORTANT: Make sure your monitoring system is running!")
    print()
    
    print("Available activities:")
    print("1. Single test run (all activities once)")
    print("2. Malicious port connections")
    print("3. Port scanning simulation")
    print("4. Data exfiltration simulation")
    print("5. Stealth connection patterns")
    print("6. nmap scan (if available)")
    print("7. Continuous suspicious activity")
    print("8. Exit")
    
    while True:
        try:
            choice = input("\nChoose an option (1-8): ").strip()
            
            if choice == '1':
                print("\n🚀 Running complete test suite...")
                test_malicious_ports()
                rapid_port_scan()
                create_suspicious_udp_traffic()
                simulate_data_exfiltration()
                create_stealth_connections()
                
                print("\n✅ Complete test suite finished!")
                print("Check your monitoring dashboard for detected anomalies.")
                
            elif choice == '2':
                test_malicious_ports()
                
            elif choice == '3':
                rapid_port_scan()
                
            elif choice == '4':
                simulate_data_exfiltration()
                
            elif choice == '5':
                create_stealth_connections()
                
            elif choice == '6':
                run_nmap_scan()
                
            elif choice == '7':
                continuous_suspicious_activity()
                
            elif choice == '8':
                print("👋 Exiting")
                break
                
            else:
                print("Invalid choice. Please enter 1-8.")
                
        except KeyboardInterrupt:
            print("\n👋 Exiting")
            break
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    main()