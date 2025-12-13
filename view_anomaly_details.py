#!/usr/bin/env python3
"""
View Detailed Anomaly Information
Shows exactly what's causing the port scan alerts
"""

import requests
import json
import time
from datetime import datetime

def get_anomaly_details():
    """Fetch detailed anomaly information from the monitoring system"""
    try:
        # Assuming the web app is running on localhost:5000
        response = requests.get('http://localhost:5000/api/anomaly_details', timeout=5)
        
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error fetching anomaly details: {response.status_code}")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"Could not connect to monitoring system: {e}")
        print("Make sure the web application is running on localhost:5000")
        return None

def display_anomaly_details(data):
    """Display detailed anomaly information in a readable format"""
    if not data or data.get('status') != 'success':
        print("No anomaly data available or monitoring not active")
        return
    
    print("=" * 80)
    print("DETAILED ANOMALY ANALYSIS")
    print("=" * 80)
    print()
    
    # Summary information
    total_anomalies = data.get('total_anomalies', 0)
    summary = data.get('summary', {})
    
    print(f"📊 SUMMARY:")
    print(f"   Total Anomalies Detected: {total_anomalies}")
    print(f"   Recent Anomalies Shown: {len(data.get('recent_anomalies', []))}")
    print()
    
    if summary.get('threat_categories'):
        print("🎯 THREAT CATEGORIES:")
        for category, count in summary['threat_categories'].items():
            print(f"   • {category.replace('_', ' ').title()}: {count}")
        print()
    
    if summary.get('top_risk_indicators'):
        print("⚠️  TOP RISK INDICATORS:")
        for indicator, count in list(summary['top_risk_indicators'].items())[:5]:
            print(f"   • {indicator.replace('_', ' ').title()}: {count}")
        print()
    
    if summary.get('processes_involved'):
        print("🔍 PROCESSES INVOLVED:")
        for process, count in list(summary['processes_involved'].items())[:5]:
            print(f"   • {process}: {count} anomalies")
        print()
    
    # Detailed anomalies
    recent_anomalies = data.get('recent_anomalies', [])
    if recent_anomalies:
        print("=" * 80)
        print("RECENT ANOMALY DETAILS")
        print("=" * 80)
        
        for i, anomaly in enumerate(recent_anomalies[-5:], 1):  # Show last 5
            print(f"\n🚨 ANOMALY #{anomaly.get('anomaly_id', i)}")
            print(f"   Time: {anomaly.get('detection_time', 'unknown')}")
            
            # Packet information
            packet = anomaly.get('packet_info', {})
            print(f"   Connection: {packet.get('src_ip', 'unknown')}:{packet.get('src_port', '?')} → {packet.get('dst_ip', 'unknown')}:{packet.get('dst_port', '?')}")
            print(f"   Protocol: {packet.get('transport', 'unknown')}/{packet.get('protocol', 'unknown')}")
            print(f"   Flags: {packet.get('flags', 'none')}")
            print(f"   Size: {packet.get('size', 0)} bytes")
            
            # Risk analysis
            risk = anomaly.get('risk_analysis', {})
            print(f"   Threat Type: {risk.get('threat_category', 'unknown').replace('_', ' ').title()}")
            print(f"   Risk Score: {risk.get('risk_score', 0)}")
            
            # Process information
            process = anomaly.get('process_info', {})
            print(f"   Process: {process.get('name', 'unknown')} (PID: {process.get('pid', 'unknown')})")
            if process.get('cmdline') and process['cmdline'] != 'unknown':
                print(f"   Command: {process['cmdline']}")
            
            # Context
            context = anomaly.get('context', {})
            print(f"   Port Type: {context.get('port_classification', 'unknown')}")
            print(f"   Direction: {'Internal' if context.get('is_internal_src') else 'External'} → {'Internal' if context.get('is_internal_dst') else 'External'}")
            
            # Explanation
            explanation = anomaly.get('explanation', 'No explanation available')
            print(f"   📝 Why Flagged: {explanation}")
            
            print("   " + "-" * 60)
    
    print("\n" + "=" * 80)
    print("RECOMMENDATIONS")
    print("=" * 80)
    
    # Generate recommendations based on the data
    if summary.get('processes_involved'):
        top_process = list(summary['processes_involved'].keys())[0]
        if top_process in ['svchost.exe', 'System', 'chrome.exe', 'firefox.exe', 'msedge.exe']:
            print("🟢 Most anomalies are from legitimate Windows/browser processes.")
            print("   This suggests the detection algorithm may need fine-tuning.")
        else:
            print(f"🟡 Most anomalies involve '{top_process}' - investigate this process.")
    
    if summary.get('threat_categories'):
        top_threat = list(summary['threat_categories'].keys())[0]
        if top_threat == 'port_scan':
            print("🔍 Port scan alerts are most common.")
            print("   Check if these are legitimate service discovery or actual attacks.")
        elif top_threat == 'malicious_service':
            print("🚨 Connections to malicious ports detected - investigate immediately!")
    
    print("\n💡 To reduce false positives:")
    print("   • Review the processes causing alerts")
    print("   • Whitelist legitimate applications")
    print("   • Adjust detection sensitivity if needed")

def monitor_live_anomalies():
    """Monitor anomalies in real-time"""
    print("🔄 Starting live anomaly monitoring...")
    print("Press Ctrl+C to stop")
    print()
    
    last_count = 0
    
    try:
        while True:
            data = get_anomaly_details()
            if data and data.get('status') == 'success':
                current_count = data.get('total_anomalies', 0)
                
                if current_count > last_count:
                    new_anomalies = current_count - last_count
                    print(f"🚨 {new_anomalies} NEW ANOMAL{'Y' if new_anomalies == 1 else 'IES'} DETECTED!")
                    
                    # Show the latest anomaly details
                    recent = data.get('recent_anomalies', [])
                    if recent:
                        latest = recent[-1]
                        packet = latest.get('packet_info', {})
                        process = latest.get('process_info', {})
                        print(f"   Latest: {packet.get('src_ip')}:{packet.get('src_port')} → {packet.get('dst_ip')}:{packet.get('dst_port')}")
                        print(f"   Process: {process.get('name', 'unknown')}")
                        print(f"   Reason: {latest.get('explanation', 'unknown')}")
                        print()
                    
                    last_count = current_count
                
            time.sleep(5)  # Check every 5 seconds
            
    except KeyboardInterrupt:
        print("\n👋 Monitoring stopped.")

def main():
    print("🔍 Network Anomaly Detail Viewer")
    print("=" * 40)
    print()
    print("1. View current anomaly details")
    print("2. Monitor live anomalies")
    print("3. Export anomaly report")
    print()
    
    choice = input("Choose an option (1-3): ").strip()
    
    if choice == '1':
        print("\n📋 Fetching current anomaly details...")
        data = get_anomaly_details()
        if data:
            display_anomaly_details(data)
        
    elif choice == '2':
        monitor_live_anomalies()
        
    elif choice == '3':
        print("\n📄 Exporting anomaly report...")
        try:
            response = requests.get('http://localhost:5000/api/export_anomaly_report', timeout=5)
            if response.status_code == 200:
                result = response.json()
                print(f"✅ Report exported: {result.get('filename', 'unknown')}")
            else:
                print(f"❌ Export failed: {response.status_code}")
        except Exception as e:
            print(f"❌ Export error: {e}")
    
    else:
        print("Invalid choice. Please run the script again.")

if __name__ == "__main__":
    main()