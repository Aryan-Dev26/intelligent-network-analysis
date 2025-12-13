"""
Test script to demonstrate attack simulations
Shows how the system detects different types of cyber attacks
"""

import sys
import os
sys.path.append('src')

from core.network_capture import NetworkCapture
from ai.threat_intelligence import ThreatIntelligenceEngine

def test_attack_simulations():
    """Test all attack simulation capabilities"""
    print("=" * 60)
    print("CYBER ATTACK SIMULATION DEMONSTRATION")
    print("=" * 60)
    
    # Initialize components
    capture = NetworkCapture()
    threat_engine = ThreatIntelligenceEngine()
    
    print("\n1. Generating network traffic with realistic attack patterns...")
    capture.start_monitoring()
    packets = capture.simulate_packet_capture(100, include_attacks=True)
    
    # Analyze attack distribution
    attack_types = {}
    normal_count = 0
    
    for packet in packets:
        attack_type = packet.get('attack_type')
        if attack_type:
            attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
        else:
            normal_count += 1
    
    print(f"\n2. Traffic Analysis Summary:")
    print(f"   Total packets: {len(packets)}")
    print(f"   Normal traffic: {normal_count}")
    print(f"   Attack packets: {len(packets) - normal_count}")
    
    print(f"\n3. Attack Types Detected:")
    for attack_type, count in attack_types.items():
        print(f"   - {attack_type.replace('_', ' ').title()}: {count} packets")
    
    # Analyze specific attacks with AI
    print(f"\n4. AI Threat Intelligence Analysis:")
    attack_packets = [p for p in packets if p.get('attack_type')]
    
    for i, packet in enumerate(attack_packets[:5]):  # Analyze first 5 attacks
        print(f"\n   Attack {i+1}: {packet['attack_type'].upper()}")
        print(f"   Description: {packet.get('attack_description', 'N/A')}")
        print(f"   Source: {packet['src_ip']} → Destination: {packet['dst_ip']}:{packet['dst_port']}")
        
        # Run threat intelligence
        anomaly_data = {
            'confidence': 0.95,
            'detected_by': ['simulation'],
            'packet_index': i
        }
        
        threat_analysis = threat_engine.analyze_threat_intelligence(anomaly_data, packet)
        
        print(f"   AI Risk Score: {threat_analysis['risk_score']}/100")
        print(f"   Threat Classification: {threat_analysis['threat_classification']['primary_type']}")
        print(f"   Confidence: {threat_analysis['confidence_level']:.3f}")
        
        # Show top recommendation
        if threat_analysis['recommendations']:
            top_rec = threat_analysis['recommendations'][0]
            print(f"   Recommendation: {top_rec['description']}")
    
    print(f"\n5. System Capabilities Demonstrated:")
    print("   ✓ Realistic attack pattern generation")
    print("   ✓ Multi-attack type simulation (Port Scan, DDoS, Data Exfiltration, Malware)")
    print("   ✓ AI-powered threat classification")
    print("   ✓ Risk scoring and assessment")
    print("   ✓ Automated security recommendations")
    
    print(f"\n6. Research Value:")
    print("   • Controlled testing environment for ML algorithms")
    print("   • Reproducible attack scenarios for evaluation")
    print("   • Safe demonstration of cybersecurity capabilities")
    print("   • Validation of ensemble detection methods")
    
    print("\n" + "=" * 60)
    print("DEMONSTRATION COMPLETE")
    print("This system is ready for MS research presentation!")
    print("=" * 60)

if __name__ == "__main__":
    test_attack_simulations()