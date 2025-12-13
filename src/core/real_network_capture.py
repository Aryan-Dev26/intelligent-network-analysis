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
        
        # Detailed anomaly tracking
        self.anomaly_details = deque(maxlen=1000)  # Store detailed anomaly information
        self.anomaly_count = 0
        self.process_mapping = {}  # Map ports to processes when possible
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
            
            # Detailed anomaly tracking
            if packet_info['is_suspicious']:
                self._log_detailed_anomaly(packet_info)
            
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
        
        dst_port = packet_info.get('dst_port', 0)
        src_port = packet_info.get('src_port', 0)
        
        # Expanded whitelist to include more legitimate services
        expanded_whitelist = [
            80, 443,           # HTTP/HTTPS
            53,                # DNS
            22,                # SSH
            21, 20,            # FTP
            25, 587, 465,      # SMTP
            993, 995, 110, 143, # Email
            123,               # NTP
            3389,              # RDP
            5985, 5986,        # WinRM
        ] + list(range(49152, 65535))  # Windows dynamic port range
        
        # Use expanded whitelist if original is too restrictive
        if self.whitelist_ports and len(self.whitelist_ports) < 10:
            # Original whitelist is too restrictive, use expanded
            active_whitelist = expanded_whitelist
        else:
            active_whitelist = self.whitelist_ports
        
        if active_whitelist:
            if dst_port not in active_whitelist and src_port not in active_whitelist:
                return False
        
        # Check packet size (more lenient)
        if packet_info.get('size', 0) > self.max_packet_size * 2:  # Allow larger packets
            return False
        
        # Don't block internal communications - they're legitimate
        # Only skip localhost if specifically requested
        src_ip = packet_info.get('src_ip', '')
        dst_ip = packet_info.get('dst_ip', '')
        
        # Only skip loopback if both are loopback (pure localhost communication)
        if ('127.0.0.1' in src_ip and '127.0.0.1' in dst_ip):
            return False
        
        return True
    
    def _analyze_packet_security(self, packet_info: Dict) -> bool:
        """Analyze packet for suspicious characteristics with improved accuracy"""
        suspicious_indicators = 0
        
        dst_port = packet_info.get('dst_port', 0)
        src_port = packet_info.get('src_port', 0)
        src_ip = packet_info.get('src_ip', '')
        dst_ip = packet_info.get('dst_ip', '')
        flags = packet_info.get('flags', '')
        size = packet_info.get('size', 0)
        
        # Define legitimate services to avoid false positives
        legitimate_ports = {
            80, 443,    # HTTP/HTTPS
            53,         # DNS
            22,         # SSH
            21, 20,     # FTP
            25, 587, 465, 993, 995, 110, 143,  # Email
            123,        # NTP
            161, 162,   # SNMP
            389, 636,   # LDAP
            3389,       # RDP
            5985, 5986, # WinRM
        }
        
        # Windows/Microsoft legitimate high ports
        windows_service_ports = range(49152, 65535)  # Windows dynamic port range
        
        # 1. Check for truly suspicious ports (not just any high port)
        malicious_ports = [4444, 5555, 6666, 1234, 31337, 12345, 6667, 6668, 1337]
        if dst_port in malicious_ports or src_port in malicious_ports:
            suspicious_indicators += 2  # High weight for known bad ports
        
        # 2. Improved port scan detection - look for patterns, not individual packets
        # Only flag as port scan if it's NOT to legitimate services
        if flags == 'SYN' and dst_port not in legitimate_ports:
            # Additional checks for real port scans
            if dst_port < 1024 and dst_port not in [22, 23, 25, 53, 80, 110, 143, 443, 993, 995]:
                suspicious_indicators += 1
        
        # 3. Check for suspicious flag combinations (actual attack patterns)
        if 'RST' in flags and 'SYN' in flags:  # Invalid flag combination
            suspicious_indicators += 2
        if 'FIN' in flags and 'SYN' in flags:  # Stealth scan
            suspicious_indicators += 2
        if flags == 'FIN':  # FIN scan
            suspicious_indicators += 1
        
        # 4. Size-based detection (more refined)
        if size < 20:  # Unusually small packets
            suspicious_indicators += 1
        elif size > 1500:  # Larger than standard MTU
            suspicious_indicators += 1
        
        # 5. IP-based checks (if not anonymized)
        if not self.anonymize_ips:
            # Check for external IPs scanning internal networks
            if self._is_external_ip(src_ip) and self._is_internal_ip(dst_ip):
                if dst_port not in legitimate_ports:
                    suspicious_indicators += 2
        
        # 6. Frequency-based detection would go here (requires state tracking)
        # For now, we'll be more conservative
        
        # Balanced threshold - catch real threats but reduce false positives
        return suspicious_indicators >= 2
    
    def _get_risk_indicators(self, packet_info: Dict) -> List[str]:
        """Get list of risk indicators for the packet with improved accuracy"""
        indicators = []
        
        dst_port = packet_info.get('dst_port', 0)
        src_port = packet_info.get('src_port', 0)
        size = packet_info.get('size', 0)
        flags = packet_info.get('flags', '')
        src_ip = packet_info.get('src_ip', '')
        dst_ip = packet_info.get('dst_ip', '')
        
        # Define legitimate services
        legitimate_ports = {80, 443, 53, 22, 21, 25, 587, 465, 993, 995, 110, 143, 123}
        malicious_ports = [4444, 5555, 6666, 1234, 31337, 12345, 6667, 6668, 1337]
        
        # 1. Truly suspicious ports only
        if dst_port in malicious_ports or src_port in malicious_ports:
            indicators.append('known_malicious_port')
        
        # 2. Refined port scan detection
        if flags == 'SYN' and dst_port not in legitimate_ports and dst_port < 1024:
            indicators.append('potential_port_scan')
        
        # 3. Stealth scan techniques
        if 'RST' in flags and 'SYN' in flags:
            indicators.append('invalid_flag_combination')
        if 'FIN' in flags and 'SYN' in flags:
            indicators.append('stealth_scan_attempt')
        if flags == 'FIN' and dst_port not in legitimate_ports:
            indicators.append('fin_scan')
        
        # 4. Size anomalies (more specific)
        if size > 1500:
            indicators.append('oversized_packet')
        elif size < 20:
            indicators.append('undersized_packet')
        
        # 5. Connection patterns
        if 'RST' in flags and dst_port in legitimate_ports:
            indicators.append('service_rejection')  # Less suspicious
        
        # 6. Remove overly broad indicators that cause false positives
        # No longer flagging normal high-port connections or simple SYN packets
        
        return indicators
    
    def _is_internal_ip(self, ip: str) -> bool:
        """Check if IP is in private/internal range"""
        if not ip or ip == "anonymized_ip":
            return True
        
        # Private IP ranges
        private_ranges = [
            ('10.0.0.0', '10.255.255.255'),
            ('172.16.0.0', '172.31.255.255'),
            ('192.168.0.0', '192.168.255.255'),
            ('127.0.0.0', '127.255.255.255'),  # Loopback
            ('169.254.0.0', '169.254.255.255'),  # Link-local
        ]
        
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except:
            return True  # Assume internal if can't parse
    
    def _is_external_ip(self, ip: str) -> bool:
        """Check if IP is external/public"""
        return not self._is_internal_ip(ip)
    
    def _log_detailed_anomaly(self, packet_info: Dict):
        """Log detailed information about detected anomalies"""
        try:
            self.anomaly_count += 1
            
            # Get process information if possible
            process_info = self._get_process_for_port(packet_info.get('src_port', 0))
            
            # Create detailed anomaly record
            anomaly_detail = {
                'anomaly_id': self.anomaly_count,
                'timestamp': packet_info['timestamp'],
                'detection_time': datetime.now().isoformat(),
                'packet_info': {
                    'src_ip': packet_info.get('src_ip', 'unknown'),
                    'dst_ip': packet_info.get('dst_ip', 'unknown'),
                    'src_port': packet_info.get('src_port', 0),
                    'dst_port': packet_info.get('dst_port', 0),
                    'protocol': packet_info.get('protocol', 'unknown'),
                    'transport': packet_info.get('transport', 'unknown'),
                    'flags': packet_info.get('flags', ''),
                    'size': packet_info.get('size', 0),
                },
                'risk_analysis': {
                    'risk_indicators': packet_info.get('risk_indicators', []),
                    'risk_score': len(packet_info.get('risk_indicators', [])),
                    'threat_category': self._categorize_threat(packet_info.get('risk_indicators', [])),
                },
                'process_info': process_info,
                'context': {
                    'is_internal_src': self._is_internal_ip(packet_info.get('src_ip', '')),
                    'is_internal_dst': self._is_internal_ip(packet_info.get('dst_ip', '')),
                    'port_classification': self._classify_port(packet_info.get('dst_port', 0)),
                    'time_of_day': datetime.now().strftime('%H:%M:%S'),
                    'day_of_week': datetime.now().strftime('%A'),
                },
                'explanation': self._generate_anomaly_explanation(packet_info)
            }
            
            # Store the detailed anomaly
            self.anomaly_details.append(anomaly_detail)
            
            # Log to console for immediate visibility
            self.logger.warning(f"ANOMALY DETECTED #{self.anomaly_count}")
            self.logger.warning(f"  Type: {anomaly_detail['risk_analysis']['threat_category']}")
            self.logger.warning(f"  Source: {packet_info.get('src_ip')}:{packet_info.get('src_port')}")
            self.logger.warning(f"  Destination: {packet_info.get('dst_ip')}:{packet_info.get('dst_port')}")
            self.logger.warning(f"  Process: {process_info.get('name', 'Unknown')} (PID: {process_info.get('pid', 'Unknown')})")
            self.logger.warning(f"  Explanation: {anomaly_detail['explanation']}")
            
        except Exception as e:
            self.logger.error(f"Error logging anomaly details: {e}")
    
    def _get_process_for_port(self, port: int) -> Dict[str, Any]:
        """Try to identify which process is using a specific port"""
        try:
            import psutil
            
            # Check if we already have this port mapped
            if port in self.process_mapping:
                return self.process_mapping[port]
            
            # Find process using this port
            for conn in psutil.net_connections(kind='inet'):
                if conn.laddr and conn.laddr.port == port:
                    try:
                        if conn.pid:
                            proc = psutil.Process(conn.pid)
                            process_info = {
                                'pid': conn.pid,
                                'name': proc.name(),
                                'exe': proc.exe() if hasattr(proc, 'exe') else 'unknown',
                                'cmdline': ' '.join(proc.cmdline()[:3]) if hasattr(proc, 'cmdline') else 'unknown',
                                'status': conn.status,
                                'create_time': proc.create_time() if hasattr(proc, 'create_time') else 0
                            }
                            
                            # Cache the result
                            self.process_mapping[port] = process_info
                            return process_info
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            
            # If no process found
            return {
                'pid': 'unknown',
                'name': 'unknown',
                'exe': 'unknown',
                'cmdline': 'unknown',
                'status': 'unknown',
                'create_time': 0
            }
            
        except Exception as e:
            return {
                'pid': 'error',
                'name': f'error: {e}',
                'exe': 'error',
                'cmdline': 'error',
                'status': 'error',
                'create_time': 0
            }
    
    def _categorize_threat(self, risk_indicators: List[str]) -> str:
        """Categorize the type of threat based on risk indicators"""
        if not risk_indicators:
            return 'unknown'
        
        # Check for specific threat patterns
        if any('scan' in indicator for indicator in risk_indicators):
            return 'port_scan'
        elif any('malicious_port' in indicator for indicator in risk_indicators):
            return 'malicious_service'
        elif any('stealth' in indicator for indicator in risk_indicators):
            return 'stealth_attack'
        elif any('oversized' in indicator for indicator in risk_indicators):
            return 'data_exfiltration'
        elif any('invalid' in indicator for indicator in risk_indicators):
            return 'protocol_anomaly'
        else:
            return 'suspicious_activity'
    
    def _classify_port(self, port: int) -> str:
        """Classify what type of service typically uses this port"""
        well_known_ports = {
            20: 'FTP Data', 21: 'FTP Control', 22: 'SSH', 23: 'Telnet',
            25: 'SMTP', 53: 'DNS', 67: 'DHCP Server', 68: 'DHCP Client',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
            993: 'IMAPS', 995: 'POP3S', 587: 'SMTP Submission',
            3389: 'RDP', 5985: 'WinRM HTTP', 5986: 'WinRM HTTPS'
        }
        
        if port in well_known_ports:
            return f"Well-known ({well_known_ports[port]})"
        elif port < 1024:
            return "System/Privileged"
        elif 1024 <= port < 49152:
            return "Registered/User"
        elif 49152 <= port <= 65535:
            return "Dynamic/Private"
        else:
            return "Unknown"
    
    def _generate_anomaly_explanation(self, packet_info: Dict) -> str:
        """Generate a human-readable explanation of why this packet was flagged"""
        risk_indicators = packet_info.get('risk_indicators', [])
        src_port = packet_info.get('src_port', 0)
        dst_port = packet_info.get('dst_port', 0)
        flags = packet_info.get('flags', '')
        
        explanations = []
        
        for indicator in risk_indicators:
            if indicator == 'known_malicious_port':
                explanations.append(f"Connection to/from known malicious port ({dst_port} or {src_port})")
            elif indicator == 'potential_port_scan':
                explanations.append(f"SYN packet to non-standard service port {dst_port}")
            elif indicator == 'stealth_scan_attempt':
                explanations.append(f"Stealth scan detected (FIN+SYN flags: {flags})")
            elif indicator == 'fin_scan':
                explanations.append(f"FIN scan detected targeting port {dst_port}")
            elif indicator == 'oversized_packet':
                explanations.append(f"Unusually large packet ({packet_info.get('size', 0)} bytes)")
            elif indicator == 'invalid_flag_combination':
                explanations.append(f"Invalid TCP flag combination: {flags}")
            else:
                explanations.append(f"Risk indicator: {indicator}")
        
        if not explanations:
            return "Packet flagged by security algorithm but no specific indicators identified"
        
        return "; ".join(explanations)
    
    def get_anomaly_details(self) -> List[Dict[str, Any]]:
        """Get detailed information about all detected anomalies"""
        return list(self.anomaly_details)
    
    def get_recent_anomalies(self, count: int = 10) -> List[Dict[str, Any]]:
        """Get the most recent anomalies with full details"""
        return list(self.anomaly_details)[-count:]
    
    def export_anomaly_report(self, filename: str = None) -> str:
        """Export detailed anomaly report to file"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"anomaly_report_{timestamp}.json"
        
        report = {
            'report_metadata': {
                'generated_at': datetime.now().isoformat(),
                'total_anomalies': self.anomaly_count,
                'monitoring_duration': str(datetime.now() - self.start_time) if self.start_time else 'unknown',
                'total_packets_analyzed': self.packet_count
            },
            'anomaly_summary': self._generate_anomaly_summary(),
            'detailed_anomalies': list(self.anomaly_details)
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.logger.info(f"Anomaly report exported to: {filename}")
        return filename
    
    def _generate_anomaly_summary(self) -> Dict[str, Any]:
        """Generate summary statistics about detected anomalies"""
        if not self.anomaly_details:
            return {'total': 0}
        
        # Analyze anomaly patterns
        threat_categories = {}
        risk_indicators = {}
        processes_involved = {}
        ports_targeted = {}
        
        for anomaly in self.anomaly_details:
            # Count threat categories
            category = anomaly['risk_analysis']['threat_category']
            threat_categories[category] = threat_categories.get(category, 0) + 1
            
            # Count risk indicators
            for indicator in anomaly['risk_analysis']['risk_indicators']:
                risk_indicators[indicator] = risk_indicators.get(indicator, 0) + 1
            
            # Count processes
            process_name = anomaly['process_info']['name']
            processes_involved[process_name] = processes_involved.get(process_name, 0) + 1
            
            # Count targeted ports
            dst_port = anomaly['packet_info']['dst_port']
            if dst_port:
                ports_targeted[dst_port] = ports_targeted.get(dst_port, 0) + 1
        
        return {
            'total': len(self.anomaly_details),
            'threat_categories': dict(sorted(threat_categories.items(), key=lambda x: x[1], reverse=True)),
            'top_risk_indicators': dict(sorted(risk_indicators.items(), key=lambda x: x[1], reverse=True)[:10]),
            'processes_involved': dict(sorted(processes_involved.items(), key=lambda x: x[1], reverse=True)[:10]),
            'most_targeted_ports': dict(sorted(ports_targeted.items(), key=lambda x: x[1], reverse=True)[:10])
        }
    
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