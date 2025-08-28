"""
Network Traffic Capture Module
Author: [Aryan Pravin Sahu]
Description: Captures and analyzes network packets for anomaly detection
"""

import time
import json
import random
import socket
from datetime import datetime
from typing import List, Dict, Any


class NetworkCapture:
    """
    Network traffic capture and basic analysis class
    
    """
    
    def __init__(self):
        self.captured_packets = []
        self.is_monitoring = False
        self.start_time = None
        
    def start_monitoring(self):
        """Start network monitoring simulation"""
        self.is_monitoring = True
        self.start_time = datetime.now()
        print(f"🚀 Network monitoring started at {self.start_time}")
        
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.is_monitoring = False
        end_time = datetime.now()
        duration = end_time - self.start_time
        print(f"⏹️ Monitoring stopped. Duration: {duration}")
        
    def simulate_packet_capture(self, num_packets: int = 100) -> List[Dict[str, Any]]:
        """
        Simulate network packet capture for development
        In real implementation, this would use scapy or similar library
        """
        packets = []
        
        # Common protocols and ports for realistic simulation
        protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'FTP']
        common_ports = [80, 443, 22, 21, 53, 8080, 3000, 5000]
        
        print(f"📡 Simulating capture of {num_packets} packets...")
        
        for i in range(num_packets):
            packet = {
                'id': i + 1,
                'timestamp': datetime.now().isoformat(),
                'src_ip': self._generate_ip(),
                'dst_ip': self._generate_ip(),
                'src_port': random.randint(1024, 65535),
                'dst_port': random.choice(common_ports),
                'protocol': random.choice(protocols),
                'size': random.randint(64, 1500),
                'flags': self._generate_flags(),
                'payload_preview': f"data_packet_{i}",
                'is_suspicious': random.random() < 0.05  # 5% suspicious packets
            }
            packets.append(packet)
            
            # Show progress for every 20 packets
            if (i + 1) % 20 == 0:
                print(f"   📦 Captured {i + 1}/{num_packets} packets")
                
        self.captured_packets.extend(packets)
        print(f"✅ Capture complete! Total packets: {len(self.captured_packets)}")
        return packets
        
    def _generate_ip(self) -> str:
        """Generate realistic IP addresses"""
        # Mix of internal and external IPs
        if random.random() < 0.7:  # 70% internal network
            return f"192.168.{random.randint(1, 255)}.{random.randint(1, 254)}"
        else:  # 30% external
            return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            
    def _generate_flags(self) -> str:
        """Generate TCP flags"""
        flags = ['SYN', 'ACK', 'FIN', 'RST', 'PSH', 'URG']
        return ','.join(random.sample(flags, random.randint(1, 3)))
        
    def get_basic_stats(self) -> Dict[str, Any]:
        """Get basic statistics about captured traffic"""
        if not self.captured_packets:
            return {"error": "No packets captured yet"}
            
        total_packets = len(self.captured_packets)
        suspicious_count = sum(1 for p in self.captured_packets if p['is_suspicious'])
        
        protocols = {}
        total_size = 0
        
        for packet in self.captured_packets:
            # Count protocols
            protocol = packet['protocol']
            protocols[protocol] = protocols.get(protocol, 0) + 1
            total_size += packet['size']
            
        return {
            'total_packets': total_packets,
            'suspicious_packets': suspicious_count,
            'suspicious_percentage': round((suspicious_count / total_packets) * 100, 2),
            'protocols': protocols,
            'average_packet_size': round(total_size / total_packets, 2),
            'total_traffic_kb': round(total_size / 1024, 2),
            'capture_duration': str(datetime.now() - self.start_time) if self.start_time else 'Not started'
        }
        
    def save_to_file(self, filename: str = None):
        """Save captured packets to JSON file"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"data/raw/network_capture_{timestamp}.json"
            
        with open(filename, 'w') as f:
            json.dump({
                'metadata': {
                    'capture_time': self.start_time.isoformat() if self.start_time else None,
                    'total_packets': len(self.captured_packets),
                    'file_created': datetime.now().isoformat()
                },
                'packets': self.captured_packets
            }, f, indent=2)
            
        print(f"💾 Data saved to: {filename}")
        return filename
        
    def detect_simple_anomalies(self) -> List[Dict[str, Any]]:
        """Simple rule-based anomaly detection"""
        anomalies = []
        
        for packet in self.captured_packets:
            reasons = []
            
            # Rule 1: Unusually large packets
            if packet['size'] > 1400:
                reasons.append("Large packet size")
                
            # Rule 2: Suspicious ports
            suspicious_ports = [4444, 5555, 6666, 1234]
            if packet['dst_port'] in suspicious_ports:
                reasons.append("Suspicious destination port")
                
            # Rule 3: Already marked as suspicious
            if packet['is_suspicious']:
                reasons.append("Flagged by initial detection")
                
            if reasons:
                anomalies.append({
                    'packet_id': packet['id'],
                    'src_ip': packet['src_ip'],
                    'dst_ip': packet['dst_ip'],
                    'reasons': reasons,
                    'risk_level': len(reasons)  # More reasons = higher risk
                })
                
        return anomalies


def demo_network_analysis():
    """
    Demo function to show the network capture in action
    Run this to test your first module!
    """
    print("=" * 50)
    print("🎯 NETWORK ANALYSIS DEMO")
    print("=" * 50)
    
    # Create network capture instance
    analyzer = NetworkCapture()
    
    # Start monitoring
    analyzer.start_monitoring()
    time.sleep(1)  # Simulate monitoring time
    
    # Capture some packets
    packets = analyzer.simulate_packet_capture(50)
    
    # Get statistics
    stats = analyzer.get_basic_stats()
    print("\n📊 NETWORK STATISTICS:")
    print(f"   Total Packets: {stats['total_packets']}")
    print(f"   Suspicious: {stats['suspicious_packets']} ({stats['suspicious_percentage']}%)")
    print(f"   Average Size: {stats['average_packet_size']} bytes")
    print(f"   Total Traffic: {stats['total_traffic_kb']} KB")
    
    print("\n🔍 PROTOCOL BREAKDOWN:")
    for protocol, count in stats['protocols'].items():
        percentage = round((count / stats['total_packets']) * 100, 1)
        print(f"   {protocol}: {count} packets ({percentage}%)")
    
    # Detect anomalies
    anomalies = analyzer.detect_simple_anomalies()
    print(f"\n🚨 ANOMALIES DETECTED: {len(anomalies)}")
    
    if anomalies:
        print("   Top 3 Suspicious Activities:")
        for i, anomaly in enumerate(anomalies[:3], 1):
            print(f"   {i}. Packet {anomaly['packet_id']}: {anomaly['src_ip']} → {anomaly['dst_ip']}")
            print(f"      Reasons: {', '.join(anomaly['reasons'])}")
    
    # Save data
    filename = analyzer.save_to_file()
    
    analyzer.stop_monitoring()
    
    print("\n🎉 Demo complete! Your first module is working!")
    print(f"📁 Data saved to: {filename}")
    

# Test the module when run directly
if __name__ == "__main__":
    demo_network_analysis()