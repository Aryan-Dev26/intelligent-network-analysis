#!/usr/bin/env python3
"""
Inject Test Anomalies Directly into Monitoring System
Creates realistic anomaly data for testing the detection and UI
"""

import sys
import os
import time
import json
from datetime import datetime, timedelta
import random

sys.path.append('src')

def inject_anomalies_to_system():
    """Inject test anomalies directly into the monitoring system"""
    
    try:
        from core.real_network_capture import RealNetworkCapture
        
        print("🧪 Injecting Test Anomalies into Monitoring System")
        print("=" * 60)
        
        # Create a capture instance
        capture = RealNetworkCapture()
        
        # Define realistic anomaly scenarios
        anomaly_scenarios = [
            {
                'name': 'Backdoor Connection Attempt',
                'packet': {
                    'id': 1001,
                    'timestamp': datetime.now().isoformat(),
                    'src_ip': '192.168.1.100',
                    'dst_ip': '10.0.0.50',
                    'src_port': 54321,
                    'dst_port': 4444,  # Known backdoor port
                    'protocol': 'TCP',
                    'transport': 'TCP',
                    'flags': 'SYN',
                    'size': 60,
                    'is_suspicious': True,
                    'risk_indicators': ['known_malicious_port']
                }
            },
            {
                'name': 'Stealth Port Scan',
                'packet': {
                    'id': 1002,
                    'timestamp': (datetime.now() + timedelta(seconds=5)).isoformat(),
                    'src_ip': '203.0.113.45',  # External IP
                    'dst_ip': '192.168.1.100',
                    'src_port': 45678,
                    'dst_port': 22,
                    'protocol': 'TCP',
                    'transport': 'TCP',
                    'flags': 'FIN,SYN',  # Invalid combination
                    'size': 40,
                    'is_suspicious': True,
                    'risk_indicators': ['stealth_scan_attempt']
                }
            },
            {
                'name': 'Data Exfiltration Attempt',
                'packet': {
                    'id': 1003,
                    'timestamp': (datetime.now() + timedelta(seconds=10)).isoformat(),
                    'src_ip': '192.168.1.100',
                    'dst_ip': '198.51.100.25',
                    'src_port': 55555,
                    'dst_port': 5555,  # Suspicious port
                    'protocol': 'TCP',
                    'transport': 'TCP',
                    'flags': 'PSH,ACK',
                    'size': 1800,  # Large packet
                    'is_suspicious': True,
                    'risk_indicators': ['known_malicious_port', 'oversized_packet']
                }
            },
            {
                'name': 'Trojan Communication',
                'packet': {
                    'id': 1004,
                    'timestamp': (datetime.now() + timedelta(seconds=15)).isoformat(),
                    'src_ip': '192.168.1.100',
                    'dst_ip': '203.0.113.100',
                    'src_port': 49152,
                    'dst_port': 31337,  # Elite/leet port
                    'protocol': 'TCP',
                    'transport': 'TCP',
                    'flags': 'SYN',
                    'size': 120,
                    'is_suspicious': True,
                    'risk_indicators': ['known_malicious_port']
                }
            },
            {
                'name': 'Suspicious FIN Scan',
                'packet': {
                    'id': 1005,
                    'timestamp': (datetime.now() + timedelta(seconds=20)).isoformat(),
                    'src_ip': '198.51.100.50',
                    'dst_ip': '192.168.1.100',
                    'src_port': 12345,
                    'dst_port': 135,  # Windows RPC
                    'protocol': 'TCP',
                    'transport': 'TCP',
                    'flags': 'FIN',
                    'size': 40,
                    'is_suspicious': True,
                    'risk_indicators': ['fin_scan']
                }
            }
        ]
        
        print(f"Injecting {len(anomaly_scenarios)} test anomalies...")
        
        for i, scenario in enumerate(anomaly_scenarios, 1):
            print(f"\n{i}. Injecting: {scenario['name']}")
            packet = scenario['packet']
            
            # Log the anomaly
            capture._log_detailed_anomaly(packet)
            
            print(f"   ✓ Anomaly #{capture.anomaly_count} logged")
            print(f"   Connection: {packet['src_ip']}:{packet['src_port']} → {packet['dst_ip']}:{packet['dst_port']}")
            print(f"   Risk: {packet['risk_indicators']}")
            
            # Small delay between injections
            time.sleep(1)
        
        print(f"\n✅ Successfully injected {capture.anomaly_count} anomalies!")
        
        # Show summary
        summary = capture._generate_anomaly_summary()
        print(f"\nAnomaly Summary:")
        print(f"  Total: {summary['total']}")
        print(f"  Threat Categories: {summary.get('threat_categories', {})}")
        print(f"  Top Risk Indicators: {summary.get('top_risk_indicators', {})}")
        
        # Export report
        filename = capture.export_anomaly_report()
        print(f"\n📄 Detailed report exported to: {filename}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error injecting anomalies: {e}")
        import traceback
        traceback.print_exc()
        return False

def create_realistic_attack_scenario():
    """Create a realistic multi-stage attack scenario"""
    
    print("\n🎯 Creating Realistic Attack Scenario")
    print("=" * 50)
    
    try:
        from core.real_network_capture import RealNetworkCapture
        capture = RealNetworkCapture()
        
        # Multi-stage attack simulation
        attack_stages = [
            {
                'stage': 'Reconnaissance',
                'packets': [
                    {
                        'timestamp': datetime.now().isoformat(),
                        'src_ip': '203.0.113.25',
                        'dst_ip': '192.168.1.100',
                        'src_port': 45678, 'dst_port': 22,
                        'protocol': 'TCP', 'flags': 'SYN', 'size': 60,
                        'is_suspicious': True, 'risk_indicators': ['potential_port_scan']
                    },
                    {
                        'timestamp': (datetime.now() + timedelta(seconds=1)).isoformat(),
                        'src_ip': '203.0.113.25',
                        'dst_ip': '192.168.1.100',
                        'src_port': 45679, 'dst_port': 80,
                        'protocol': 'TCP', 'flags': 'SYN', 'size': 60,
                        'is_suspicious': True, 'risk_indicators': ['potential_port_scan']
                    }
                ]
            },
            {
                'stage': 'Exploitation',
                'packets': [
                    {
                        'timestamp': (datetime.now() + timedelta(seconds=30)).isoformat(),
                        'src_ip': '203.0.113.25',
                        'dst_ip': '192.168.1.100',
                        'src_port': 45680, 'dst_port': 4444,
                        'protocol': 'TCP', 'flags': 'SYN', 'size': 60,
                        'is_suspicious': True, 'risk_indicators': ['known_malicious_port']
                    }
                ]
            },
            {
                'stage': 'Command & Control',
                'packets': [
                    {
                        'timestamp': (datetime.now() + timedelta(minutes=1)).isoformat(),
                        'src_ip': '192.168.1.100',
                        'dst_ip': '203.0.113.25',
                        'src_port': 49152, 'dst_port': 31337,
                        'protocol': 'TCP', 'flags': 'PSH,ACK', 'size': 200,
                        'is_suspicious': True, 'risk_indicators': ['known_malicious_port']
                    }
                ]
            },
            {
                'stage': 'Data Exfiltration',
                'packets': [
                    {
                        'timestamp': (datetime.now() + timedelta(minutes=2)).isoformat(),
                        'src_ip': '192.168.1.100',
                        'dst_ip': '203.0.113.25',
                        'src_port': 49153, 'dst_port': 5555,
                        'protocol': 'TCP', 'flags': 'PSH,ACK', 'size': 1900,
                        'is_suspicious': True, 'risk_indicators': ['known_malicious_port', 'oversized_packet']
                    }
                ]
            }
        ]
        
        total_packets = 0
        
        for stage_info in attack_stages:
            stage_name = stage_info['stage']
            packets = stage_info['packets']
            
            print(f"\n📍 Stage: {stage_name}")
            
            for packet in packets:
                # Add required fields
                packet['id'] = 2000 + total_packets
                packet['transport'] = 'TCP'
                
                capture._log_detailed_anomaly(packet)
                total_packets += 1
                
                print(f"   ✓ {packet['src_ip']}:{packet['src_port']} → {packet['dst_ip']}:{packet['dst_port']}")
        
        print(f"\n✅ Attack scenario complete! {total_packets} suspicious packets logged")
        
        return True
        
    except Exception as e:
        print(f"❌ Error creating attack scenario: {e}")
        return False

def main():
    print("🎯 Anomaly Injection Tool")
    print("=" * 40)
    print("This tool injects test anomalies directly into your monitoring system")
    print("so you can see the detection and analysis features working.")
    print()
    
    print("Options:")
    print("1. Inject basic test anomalies")
    print("2. Create realistic attack scenario")
    print("3. Both (recommended)")
    print("4. Exit")
    
    while True:
        try:
            choice = input("\nChoose an option (1-4): ").strip()
            
            if choice == '1':
                success = inject_anomalies_to_system()
                if success:
                    print("\n🎉 Test anomalies injected!")
                    print("Check your web dashboard to see the detected anomalies.")
                
            elif choice == '2':
                success = create_realistic_attack_scenario()
                if success:
                    print("\n🎉 Attack scenario created!")
                    print("Check your web dashboard for the multi-stage attack detection.")
                
            elif choice == '3':
                print("\n🚀 Running complete test suite...")
                success1 = inject_anomalies_to_system()
                success2 = create_realistic_attack_scenario()
                
                if success1 and success2:
                    print("\n🎉 Complete test suite executed!")
                    print("Your monitoring system now has comprehensive test data.")
                    print("Check the web dashboard and anomaly details section.")
                
            elif choice == '4':
                print("👋 Exiting")
                break
                
            else:
                print("Invalid choice. Please enter 1-4.")
                
        except KeyboardInterrupt:
            print("\n👋 Exiting")
            break
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    main()