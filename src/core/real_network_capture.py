"""
Real Network Traffic Capture Module
SECURITY WARNING: This module captures actual network traffic
Author: Aryan Pravin Sahu
"""

import time
import json
import threading
from datetime import datetime
from typing import List, Dict, Any, Optional
import socket
import struct
import logging
from collections import deque

# Optional: Use scapy for advanced packet capture
try:
    from scapy.all import sniff, IP, TCP, UDP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("WARNING: Scapy not installed. Real packet capture will be limited.")
    print("Install with: pip install scapy")

class RealNetworkCapture:
    """
    Real network traffic capture with security controls
    IMPORTANT: Only use on networks you own or have permission to monitor
    """
    
    def __init__(self, interface: str = None, capture_filter: str = None):
        self.interface = interface  # Network interface (e.g., 'eth0', 'wlan0')
        self.capture_filter = capture_filter or "tcp or udp"  # BPF filter
        self.captured_packets = deque(maxlen=10000)  # Limit memory usage
        self.is_monitoring = False
        self.capture_thread = None
        self.packet_count = 0
        self.start_time = None
        
        # Security settings
        self.anonymize_ips = True  # Anonymize IP addresses by default
        self.capture_payload = False  # Don't capture payload by default
        self.whitelist_ports = [80, 443, 53, 22, 21, 25]  # Only monitor common ports
        self.max_packet_size = 1500  # Limit packet size capture
        
        # Logging setup
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        # Security checks
        self._perform_security_checks()
    
    def _perform_security_checks(self):
        """Perform security checks before starting capture"""
        import os
        import getpass
        
        # Check if running as administrator/root (required for packet capture)
        if os.name == 'nt':  # Windows
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                self.logger.warning("Administrator privileges required for packet capture on Windows")
        else:  # Unix-like systems
            if os.geteuid() != 0:
                self.logger.warning("Root privileges may be required for packet capture on Unix systems")
        
        # Log security settings
        self.logger.info("Security Settings:")
        self.logger.info(f"  IP Anonymization: {self.anonymize_ips}")
        self.logger.info(f"  Payload Capture: {self.capture_payload}")
        self.logger.info(f"  Port Whitelist: {self.whitelist_ports}")
        self.logger.info(f"  Max Packet Size: {self.max_packet_size}")
    
    def start_monitoring(self, duration: Optional[int] = None):
        """
        Start real network monitoring
        
        Args:
            duration: Optional duration in seconds (None for continuous)
        """
        if self.is_monitoring:
            self.logger.warning("Monitoring already in progress")
            return
        
        if not SCAPY_AVAILABLE:
            self.logger.error("Scapy not available. Cannot capture real network traffic.")
            return False
        
        self.is_monitoring = True
        self.start_time = datetime.now()
        self.packet_count = 0
        
        self.logger.info(f"Starting real network capture on interface: {self.interface or 'default'}")
        self.logger.info(f"Filter: {self.capture_filter}")
        
        # Start capture in separate thread
        self.capture_thread = threading.Thread(
            target=self._capture_packets,
            args=(duration,),
            daemon=True
        )
        self.capture_thread.start()
        
        return True
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        if not self.is_monitoring:
            return
        
        self.is_monitoring = False
        end_time = datetime.now()
        duration = end_time - self.start_time if self.start_time else 0
        
        self.logger.info(f"Monitoring stopped. Duration: {duration}")
        self.logger.info(f"Packets captured: {self.packet_count}")
        
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=5)
    
    def _capture_packets(self, duration: Optional[int]):
        """Internal method to capture packets using Scapy"""
        try:
            # Configure packet capture
            sniff_kwargs = {
                'prn': self._process_packet,
                'filter': self.capture_filter,
                'store': False,  # Don't store packets in memory (we handle this)
                'stop_filter': lambda x: not self.is_monitoring
            }
            
            if self.interface:
                sniff_kwargs['iface'] = self.interface
            
            if duration:
                sniff_kwargs['timeout'] = duration
            
            # Start packet capture
            sniff(**sniff_kwargs)
            
        except Exception as e:
            self.logger.error(f"Packet capture error: {e}")
            self.is_monitoring = False
    
    def _process_packet(self, packet):
        """Process captured packet with security controls"""
        try:
            # Basic packet info
            packet_info = {
                'id': self.packet_count + 1,
                'timestamp': datetime.now().isoformat(),
                'size': len(packet)
            }
            
            # Extract IP layer information
            if IP in packet:
                ip_layer = packet[IP]
                
                # Anonymize IP addresses if enabled
                if self.anonymize_ips:
                    packet_info['src_ip'] = self._anonymize_ip(ip_layer.src)
                    packet_info['dst_ip'] = self._anonymize_ip(ip_layer.dst)
                else:
                    packet_info['src_ip'] = ip_layer.src
                    packet_info['dst_ip'] = ip_layer.dst
                
                packet_info['protocol'] = self._get_protocol_name(ip_layer.proto)
                packet_info['ttl'] = ip_layer.ttl
            
            # Extract transport layer information
            if TCP in packet:
                tcp_layer = packet[TCP]
                packet_info['src_port'] = tcp_layer.sport
                packet_info['dst_port'] = tcp_layer.dport
                packet_info['flags'] = self._get_tcp_flags(tcp_layer.flags)
                packet_info['transport'] = 'TCP'
                
            elif UDP in packet:
                udp_layer = packet[UDP]
                packet_info['src_port'] = udp_layer.sport
                packet_info['dst_port'] = udp_layer.dport
                packet_info['flags'] = ''
                packet_info['transport'] = 'UDP'
            
            # Security filtering
            if not self._is_packet_allowed(packet_info):
                return
            
            # Add security analysis
            packet_info['is_suspicious'] = self._analyze_packet_security(packet_info)
            packet_info['risk_indicators'] = self._get_risk_indicators(packet_info)
            
            # Payload handling (if enabled and safe)
            if self.capture_payload and Raw in packet:
                payload = packet[Raw].load
                # Only capture first 100 bytes and ensure it's safe
                safe_payload = payload[:100]
                try:
                    packet_info['payload_preview'] = safe_payload.decode('utf-8', errors='ignore')[:50]
                except:
                    packet_info['payload_preview'] = f"binary_data_{len(safe_payload)}_bytes"
            else:
                packet_info['payload_preview'] = "payload_not_captured"
            
            # Add to captured packets
            self.captured_packets.append(packet_info)
            self.packet_count += 1
            
            # Log progress
            if self.packet_count % 100 == 0:
                self.logger.info(f"Captured {self.packet_count} packets")
            
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")
    
    def _anonymize_ip(self, ip_address: str) -> str:
        """Anonymize IP address for privacy"""
        parts = ip_address.split('.')
        if len(parts) == 4:
            # Keep first two octets, anonymize last two
            return f"{parts[0]}.{parts[1]}.xxx.xxx"
        return "anonymized_ip"
    
    def _get_protocol_name(self, proto_num: int) -> str:
        """Convert protocol number to name"""
        protocol_map = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP',
            47: 'GRE',
            50: 'ESP',
            51: 'AH'
        }
        return protocol_map.get(proto_num, f'PROTO_{proto_num}')
    
    def _get_tcp_flags(self, flags: int) -> str:
        """Convert TCP flags to string representation"""
        flag_names = []
        if flags & 0x01: flag_names.append('FIN')
        if flags & 0x02: flag_names.append('SYN')
        if flags & 0x04: flag_names.append('RST')
        if flags & 0x08: flag_names.append('PSH')
        if flags & 0x10: flag_names.append('ACK')
        if flags & 0x20: flag_names.append('URG')
        return ','.join(flag_names)
    
    def _is_packet_allowed(self, packet_info: Dict) -> bool:
        """Check if packet should be captured based on security rules"""
        
        # Check port whitelist
        dst_port = packet_info.get('dst_port', 0)
        src_port = packet_info.get('src_port', 0)
        
        if self.whitelist_ports:
            if dst_port not in self.whitelist_ports and src_port not in self.whitelist_ports:
                return False
        
        # Check packet size
        if packet_info.get('size', 0) > self.max_packet_size:
            return False
        
        # Block private/internal communications if anonymization is on
        if self.anonymize_ips:
            src_ip = packet_info.get('src_ip', '')
            dst_ip = packet_info.get('dst_ip', '')
            
            # Skip localhost traffic
            if '127.0.0.1' in src_ip or '127.0.0.1' in dst_ip:
                return False
        
        return True
    
    def _analyze_packet_security(self, packet_info: Dict) -> bool:
        """Analyze packet for suspicious characteristics"""
        suspicious_indicators = 0
        
        # Check for suspicious ports
        suspicious_ports = [4444, 5555, 6666, 1234, 31337, 12345]
        dst_port = packet_info.get('dst_port', 0)
        src_port = packet_info.get('src_port', 0)
        
        if dst_port in suspicious_ports or src_port in suspicious_ports:
            suspicious_indicators += 1
        
        # Check for unusual packet sizes
        size = packet_info.get('size', 0)
        if size < 40 or size > 1400:
            suspicious_indicators += 1
        
        # Check for suspicious flags
        flags = packet_info.get('flags', '')
        if 'RST' in flags and 'SYN' in flags:
            suspicious_indicators += 1
        
        return suspicious_indicators >= 2
    
    def _get_risk_indicators(self, packet_info: Dict) -> List[str]:
        """Get list of risk indicators for the packet"""
        indicators = []
        
        dst_port = packet_info.get('dst_port', 0)
        src_port = packet_info.get('src_port', 0)
        size = packet_info.get('size', 0)
        flags = packet_info.get('flags', '')
        
        # Port-based indicators
        if dst_port < 1024 and src_port > 50000:
            indicators.append('high_port_to_privileged')
        
        if dst_port in [4444, 5555, 6666]:
            indicators.append('suspicious_port')
        
        # Size-based indicators
        if size > 1400:
            indicators.append('large_packet')
        elif size < 60:
            indicators.append('small_packet')
        
        # Flag-based indicators
        if flags == 'SYN':
            indicators.append('syn_scan_possible')
        elif 'RST' in flags:
            indicators.append('connection_reset')
        
        return indicators
    
    def get_capture_statistics(self) -> Dict[str, Any]:
        """Get statistics about the capture session"""
        if not self.start_time:
            return {"error": "No capture session started"}
        
        current_time = datetime.now()
        duration = current_time - self.start_time
        
        # Analyze captured packets
        protocols = {}
        suspicious_count = 0
        port_distribution = {}
        
        for packet in self.captured_packets:
            # Protocol distribution
            protocol = packet.get('protocol', 'unknown')
            protocols[protocol] = protocols.get(protocol, 0) + 1
            
            # Suspicious packet count
            if packet.get('is_suspicious', False):
                suspicious_count += 1
            
            # Port distribution
            dst_port = packet.get('dst_port', 0)
            if dst_port:
                port_distribution[dst_port] = port_distribution.get(dst_port, 0) + 1
        
        return {
            'capture_duration': str(duration),
            'total_packets': self.packet_count,
            'packets_stored': len(self.captured_packets),
            'suspicious_packets': suspicious_count,
            'suspicious_percentage': (suspicious_count / max(1, self.packet_count)) * 100,
            'protocols': protocols,
            'top_ports': dict(sorted(port_distribution.items(), key=lambda x: x[1], reverse=True)[:10]),
            'capture_rate': self.packet_count / max(1, duration.total_seconds()),
            'is_monitoring': self.is_monitoring
        }
    
    def export_packets(self, filename: str = None, format: str = 'json') -> str:
        """Export captured packets to file"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"real_capture_{timestamp}.{format}"
        
        if format == 'json':
            with open(filename, 'w') as f:
                json.dump({
                    'metadata': {
                        'capture_start': self.start_time.isoformat() if self.start_time else None,
                        'total_packets': self.packet_count,
                        'anonymized': self.anonymize_ips,
                        'interface': self.interface,
                        'filter': self.capture_filter
                    },
                    'packets': list(self.captured_packets)
                }, f, indent=2)
        
        self.logger.info(f"Packets exported to: {filename}")
        return filename


def demo_real_capture():
    """
    Demo function for real network capture
    WARNING: This captures actual network traffic
    """
    print("=" * 60)
    print("REAL NETWORK CAPTURE DEMO")
    print("WARNING: This will capture actual network traffic!")
    print("=" * 60)
    
    # Get user confirmation
    response = input("Do you want to proceed with real network capture? (yes/no): ")
    if response.lower() != 'yes':
        print("Demo cancelled.")
        return
    
    # Initialize capture with security settings
    capture = RealNetworkCapture()
    
    # Configure security settings
    capture.anonymize_ips = True  # Always anonymize for demo
    capture.capture_payload = False  # Don't capture payload for security
    capture.whitelist_ports = [80, 443, 53]  # Only common web/DNS traffic
    
    print("\nSecurity settings:")
    print(f"  IP Anonymization: {capture.anonymize_ips}")
    print(f"  Payload Capture: {capture.capture_payload}")
    print(f"  Port Whitelist: {capture.whitelist_ports}")
    
    try:
        # Start monitoring for 30 seconds
        print("\nStarting 30-second network capture...")
        if capture.start_monitoring():
            time.sleep(30)  # Capture for 30 seconds
            capture.stop_monitoring()
            
            # Show statistics
            stats = capture.get_capture_statistics()
            print(f"\nCapture Statistics:")
            print(f"  Duration: {stats['capture_duration']}")
            print(f"  Total packets: {stats['total_packets']}")
            print(f"  Suspicious packets: {stats['suspicious_packets']}")
            print(f"  Protocols: {stats['protocols']}")
            print(f"  Top ports: {list(stats['top_ports'].keys())[:5]}")
            
            # Export data
            filename = capture.export_packets()
            print(f"\nData exported to: {filename}")
            
        else:
            print("Failed to start network capture.")
            print("Make sure you have appropriate permissions and Scapy is installed.")
    
    except KeyboardInterrupt:
        print("\nCapture interrupted by user.")
        capture.stop_monitoring()
    
    except Exception as e:
        print(f"Error during capture: {e}")
        capture.stop_monitoring()
    
    print("\nDemo completed.")


if __name__ == "__main__":
    demo_real_capture()