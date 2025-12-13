#!/usr/bin/env python3
"""
Analyze current network traffic to understand what's being detected
"""

import sys
import os
import time
sys.path.append('src')

def analyze_recent_packets():
    """Analyze the most recent packets to understand the port scan detection"""
    try:
        # Read the most recent capture data
        import json
        from datetime import datetime
        
        # Look for recent capture files
        data_dir = "data/raw"
        if os.path.exists(data_dir):
            files = [f for f in os.listdir(data_dir) if f.endswith('.json')]
            if files:
                latest_file = max(files, key=lambda x: os.path.getctime(os.path.join(data_dir, x)))
                print(f"Analyzing: {latest_file}")
                
                with open(os.path.join(data_dir, latest_file), 'r') as f:
                    data = json.load(f)
                
                packets = data.get('packets', [])
                print(f"Found {len(packets)} packets")
                
                # Analyze suspicious packets
                suspicious_packets = [p for p in packets if p.get('is_suspicious', False)]
                print(f"Suspicious packets: {len(suspicious_packets)}")
                
                for i, packet in enumerate(suspicious_packets[:5]):  # Show first 5
                    print(f"\nSuspicious Packet {i+1}:")
                    print(f"  Source: {packet.get('src_ip', 'unknown')}:{packet.get('src_port', 'unknown')}")
                    print(f"  Destination: {packet.get('dst_ip', 'unknown')}:{packet.get('dst_port', 'unknown')}")
                    print(f"  Protocol: {packet.get('protocol', 'unknown')}")
                    print(f"  Flags: {packet.get('flags', 'none')}")
                    print(f"  Risk Indicators: {packet.get('risk_indicators', [])}")
                
                return True
        
        print("No recent capture data found.")
        return False
        
    except Exception as e:
        print(f"Error analyzing packets: {e}")
        return False

def check_common_processes():
    """Check what processes might be causing network activity"""
    try:
        import psutil
        
        print("\nActive network connections:")
        connections = psutil.net_connections(kind='inet')
        
        # Group by process
        process_connections = {}
        for conn in connections[:20]:  # Limit to first 20
            try:
                if conn.pid:
                    proc = psutil.Process(conn.pid)
                    proc_name = proc.name()
                    if proc_name not in process_connections:
                        process_connections[proc_name] = []
                    process_connections[proc_name].append(conn)
            except:
                continue
        
        for proc_name, conns in list(process_connections.items())[:10]:
            print(f"\n{proc_name}: {len(conns)} connections")
            for conn in conns[:3]:  # Show first 3 connections per process
                local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "unknown"
                remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "unknown"
                print(f"  {local} -> {remote} ({conn.status})")
        
        return True
        
    except Exception as e:
        print(f"Error checking processes: {e}")
        return False

def main():
    print("=" * 60)
    print("NETWORK TRAFFIC ANALYSIS")
    print("=" * 60)
    print()
    
    print("This will help you understand what network activity is being detected.")
    print()
    
    # Analyze captured packets
    print("1. Analyzing recent packet captures...")
    if not analyze_recent_packets():
        print("   No packet data available for analysis.")
    
    print("\n" + "=" * 60)
    
    # Check active processes
    print("2. Checking active network processes...")
    check_common_processes()
    
    print("\n" + "=" * 60)
    print("INTERPRETATION:")
    print("=" * 60)
    print()
    print("Common legitimate sources of 'port scan' alerts:")
    print("• Windows Update (svchost.exe)")
    print("• Web browsers (chrome.exe, firefox.exe, msedge.exe)")
    print("• Antivirus software")
    print("• Microsoft services (various svchost processes)")
    print("• Network discovery protocols")
    print("• Background app updates")
    print()
    print("These are typically NORMAL and not actual security threats.")
    print("Real malicious port scans would show:")
    print("• Rapid sequential port attempts")
    print("• Connections to unusual port ranges")
    print("• External IP addresses scanning your system")

if __name__ == "__main__":
    main()