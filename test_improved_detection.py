#!/usr/bin/env python3
"""
Test the improved threat detection to verify it reduces false positives
"""

import sys
import os
sys.path.append('src')

from core.real_network_capture import RealNetworkCapture

def test_detection_improvements():
    """Test various packet scenarios to verify improved detection"""
    
    capture = RealNetworkCapture()
    
    # Test cases: (description, packet_info, should_be_suspicious)
    test_cases = [
        # Legitimate traffic (should NOT be flagged)
        ("Normal HTTPS connection", {
            'src_ip': '192.168.1.55', 'dst_ip': '40.74.79.222',
            'src_port': 54321, 'dst_port': 443,
            'flags': 'SYN', 'size': 60, 'protocol': 'TCP'
        }, False),
        
        ("Windows Update connection", {
            'src_ip': '192.168.1.55', 'dst_ip': '52.123.253.131',
            'src_port': 61845, 'dst_port': 443,
            'flags': 'ACK', 'size': 1200, 'protocol': 'TCP'
        }, False),
        
        ("DNS query", {
            'src_ip': '192.168.1.55', 'dst_ip': '8.8.8.8',
            'src_port': 54321, 'dst_port': 53,
            'flags': '', 'size': 64, 'protocol': 'UDP'
        }, False),
        
        ("Normal web browsing", {
            'src_ip': '192.168.1.55', 'dst_ip': '142.250.191.14',
            'src_port': 55432, 'dst_port': 80,
            'flags': 'SYN,ACK', 'size': 1460, 'protocol': 'TCP'
        }, False),
        
        # Suspicious traffic (SHOULD be flagged)
        ("Connection to known malicious port", {
            'src_ip': '192.168.1.55', 'dst_ip': '10.0.0.1',
            'src_port': 54321, 'dst_port': 4444,
            'flags': 'SYN', 'size': 60, 'protocol': 'TCP'
        }, True),
        
        ("Stealth scan attempt", {
            'src_ip': '192.168.1.55', 'dst_ip': '10.0.0.1',
            'src_port': 54321, 'dst_port': 22,
            'flags': 'FIN,SYN', 'size': 40, 'protocol': 'TCP'
        }, True),
        
        ("FIN scan to non-standard port", {
            'src_ip': '192.168.1.55', 'dst_ip': '10.0.0.1',
            'src_port': 54321, 'dst_port': 135,
            'flags': 'FIN', 'size': 40, 'protocol': 'TCP'
        }, True),
        
        ("Oversized packet", {
            'src_ip': '192.168.1.55', 'dst_ip': '10.0.0.1',
            'src_port': 54321, 'dst_port': 1337,
            'flags': 'SYN', 'size': 2000, 'protocol': 'TCP'
        }, True),
    ]
    
    print("=" * 70)
    print("TESTING IMPROVED THREAT DETECTION")
    print("=" * 70)
    print()
    
    correct_predictions = 0
    total_tests = len(test_cases)
    
    for i, (description, packet_info, expected_suspicious) in enumerate(test_cases, 1):
        # Test the detection
        is_suspicious = capture._analyze_packet_security(packet_info)
        risk_indicators = capture._get_risk_indicators(packet_info)
        
        # Check if prediction is correct
        is_correct = is_suspicious == expected_suspicious
        if is_correct:
            correct_predictions += 1
        
        # Display results
        status = "✓ CORRECT" if is_correct else "✗ WRONG"
        expected_str = "SUSPICIOUS" if expected_suspicious else "LEGITIMATE"
        actual_str = "SUSPICIOUS" if is_suspicious else "LEGITIMATE"
        
        print(f"Test {i}: {description}")
        print(f"  Expected: {expected_str}")
        print(f"  Detected: {actual_str}")
        print(f"  Risk Indicators: {risk_indicators}")
        print(f"  Result: {status}")
        print()
    
    # Summary
    accuracy = (correct_predictions / total_tests) * 100
    print("=" * 70)
    print("RESULTS SUMMARY")
    print("=" * 70)
    print(f"Correct predictions: {correct_predictions}/{total_tests}")
    print(f"Accuracy: {accuracy:.1f}%")
    print()
    
    if accuracy >= 80:
        print("✓ GOOD: Detection accuracy is acceptable")
    else:
        print("✗ NEEDS IMPROVEMENT: Detection accuracy is too low")
    
    print("\nKey improvements made:")
    print("• Removed false positive for normal HTTPS connections")
    print("• Added whitelist for legitimate services")
    print("• Increased threshold for suspicious classification")
    print("• Better distinction between scan types")
    print("• Reduced sensitivity to normal Windows traffic")

if __name__ == "__main__":
    test_detection_improvements()