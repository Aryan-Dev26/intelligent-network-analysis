"""
Security Configuration for Real Network Monitoring
Ensures safe and ethical network traffic analysis
Author: Aryan Pravin Sahu
"""

import os
import json
import hashlib
import logging
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path

class SecurityConfig:
    """
    Security configuration and compliance manager
    Ensures ethical and safe network monitoring
    """
    
    def __init__(self):
        self.config_file = Path("security_config.json")
        self.logger = logging.getLogger(__name__)
        self.default_config = self._get_default_config()
        self.config = self._load_config()
    
    def _get_default_config(self) -> Dict:
        """Get default security configuration"""
        return {
            "privacy_settings": {
                "anonymize_ips": True,
                "anonymize_mac_addresses": True,
                "capture_payload": False,
                "hash_sensitive_data": True,
                "data_retention_days": 7
            },
            "capture_limits": {
                "max_packets_per_session": 10000,
                "max_session_duration_minutes": 60,
                "max_packet_size_bytes": 1500,
                "rate_limit_packets_per_second": 1000
            },
            "network_restrictions": {
                "allowed_interfaces": [],  # Empty means auto-detect
                "blocked_ip_ranges": [
                    "127.0.0.0/8",    # Localhost
                    "169.254.0.0/16", # Link-local
                    "224.0.0.0/4"     # Multicast
                ],
                "allowed_ports": [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995],
                "blocked_ports": [135, 137, 138, 139, 445, 1433, 1521, 3306, 3389, 5432]
            },
            "compliance": {
                "require_user_consent": True,
                "log_all_activities": True,
                "encrypt_stored_data": True,
                "auto_delete_old_data": True,
                "audit_trail": True
            },
            "alerts": {
                "notify_on_suspicious_activity": True,
                "alert_threshold_packets": 1000,
                "alert_on_blocked_ports": True,
                "alert_on_large_transfers": True
            },
            "research_mode": {
                "enabled": True,
                "simulation_preferred": True,
                "real_capture_requires_approval": True,
                "academic_use_only": True
            }
        }
    
    def _load_config(self) -> Dict:
        """Load configuration from file or create default"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                self.logger.info("Security configuration loaded from file")
                return config
            except Exception as e:
                self.logger.error(f"Error loading config: {e}")
        
        # Create default config
        self._save_config(self.default_config)
        self.logger.info("Default security configuration created")
        return self.default_config
    
    def _save_config(self, config: Dict):
        """Save configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
            self.logger.info("Security configuration saved")
        except Exception as e:
            self.logger.error(f"Error saving config: {e}")
    
    def get_user_consent(self) -> bool:
        """Get explicit user consent for network monitoring"""
        if not self.config["compliance"]["require_user_consent"]:
            return True
        
        print("\n" + "=" * 60)
        print("NETWORK MONITORING CONSENT REQUIRED")
        print("=" * 60)
        print("This system will monitor network traffic for security analysis.")
        print("\nWhat will be monitored:")
        print("• Network packet headers (IP addresses, ports, protocols)")
        print("• Packet timing and size information")
        print("• Connection patterns and flow data")
        
        print("\nPrivacy protections:")
        print("• IP addresses will be anonymized" if self.config["privacy_settings"]["anonymize_ips"] else "• IP addresses will NOT be anonymized")
        print("• Packet payload will NOT be captured" if not self.config["privacy_settings"]["capture_payload"] else "• Packet payload WILL be captured")
        print(f"• Data will be automatically deleted after {self.config['privacy_settings']['data_retention_days']} days")
        
        print("\nLegal considerations:")
        print("• Only monitor networks you own or have explicit permission to monitor")
        print("• Comply with local privacy and cybersecurity laws")
        print("• This tool is for research and educational purposes only")
        
        print("\nBy proceeding, you confirm:")
        print("1. You have the right to monitor this network")
        print("2. You will use this data responsibly and ethically")
        print("3. You understand the privacy implications")
        
        while True:
            response = input("\nDo you consent to network monitoring? (yes/no): ").lower().strip()
            if response in ['yes', 'y']:
                self._log_consent(True)
                return True
            elif response in ['no', 'n']:
                self._log_consent(False)
                return False
            else:
                print("Please enter 'yes' or 'no'")
    
    def _log_consent(self, granted: bool):
        """Log user consent decision"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "consent_granted": granted,
            "user": os.getenv("USER", "unknown"),
            "session_id": hashlib.md5(str(datetime.now()).encode()).hexdigest()[:8]
        }
        
        # Append to consent log
        consent_log = Path("consent_log.json")
        logs = []
        
        if consent_log.exists():
            try:
                with open(consent_log, 'r') as f:
                    logs = json.load(f)
            except:
                pass
        
        logs.append(log_entry)
        
        try:
            with open(consent_log, 'w') as f:
                json.dump(logs, f, indent=2)
        except Exception as e:
            self.logger.error(f"Error logging consent: {e}")
    
    def validate_network_interface(self, interface: str) -> bool:
        """Validate that network interface is allowed"""
        allowed = self.config["network_restrictions"]["allowed_interfaces"]
        
        # If no specific interfaces allowed, permit any
        if not allowed:
            return True
        
        return interface in allowed
    
    def is_ip_allowed(self, ip_address: str) -> bool:
        """Check if IP address is allowed for monitoring"""
        import ipaddress
        
        blocked_ranges = self.config["network_restrictions"]["blocked_ip_ranges"]
        
        try:
            ip = ipaddress.ip_address(ip_address)
            
            for blocked_range in blocked_ranges:
                network = ipaddress.ip_network(blocked_range, strict=False)
                if ip in network:
                    return False
            
            return True
            
        except ValueError:
            # Invalid IP address
            return False
    
    def is_port_allowed(self, port: int) -> bool:
        """Check if port is allowed for monitoring"""
        allowed_ports = self.config["network_restrictions"]["allowed_ports"]
        blocked_ports = self.config["network_restrictions"]["blocked_ports"]
        
        # Check blocked ports first
        if port in blocked_ports:
            return False
        
        # If allowed ports specified, check membership
        if allowed_ports:
            return port in allowed_ports
        
        # If no specific allowed ports, allow all except blocked
        return True
    
    def get_capture_limits(self) -> Dict:
        """Get capture limits for safety"""
        return self.config["capture_limits"]
    
    def should_anonymize_data(self) -> bool:
        """Check if data should be anonymized"""
        return self.config["privacy_settings"]["anonymize_ips"]
    
    def should_capture_payload(self) -> bool:
        """Check if payload capture is allowed"""
        return self.config["privacy_settings"]["capture_payload"]
    
    def get_data_retention_days(self) -> int:
        """Get data retention period"""
        return self.config["privacy_settings"]["data_retention_days"]
    
    def cleanup_old_data(self):
        """Clean up old data files based on retention policy"""
        if not self.config["compliance"]["auto_delete_old_data"]:
            return
        
        retention_days = self.get_data_retention_days()
        cutoff_time = datetime.now().timestamp() - (retention_days * 24 * 3600)
        
        # Clean up data files
        data_patterns = ["*.json", "*.pcap", "*capture*", "*network*"]
        deleted_count = 0
        
        for pattern in data_patterns:
            for file_path in Path(".").glob(pattern):
                try:
                    if file_path.stat().st_mtime < cutoff_time:
                        file_path.unlink()
                        deleted_count += 1
                        self.logger.info(f"Deleted old data file: {file_path}")
                except Exception as e:
                    self.logger.error(f"Error deleting {file_path}: {e}")
        
        if deleted_count > 0:
            self.logger.info(f"Cleaned up {deleted_count} old data files")
    
    def create_security_report(self) -> Dict:
        """Create security compliance report"""
        return {
            "timestamp": datetime.now().isoformat(),
            "privacy_compliance": {
                "ip_anonymization": self.config["privacy_settings"]["anonymize_ips"],
                "payload_capture_disabled": not self.config["privacy_settings"]["capture_payload"],
                "data_retention_policy": f"{self.config['privacy_settings']['data_retention_days']} days",
                "automatic_cleanup": self.config["compliance"]["auto_delete_old_data"]
            },
            "network_restrictions": {
                "port_filtering": len(self.config["network_restrictions"]["allowed_ports"]) > 0,
                "ip_range_blocking": len(self.config["network_restrictions"]["blocked_ip_ranges"]) > 0,
                "interface_restrictions": len(self.config["network_restrictions"]["allowed_interfaces"]) > 0
            },
            "capture_limits": self.config["capture_limits"],
            "compliance_features": {
                "user_consent_required": self.config["compliance"]["require_user_consent"],
                "activity_logging": self.config["compliance"]["log_all_activities"],
                "audit_trail": self.config["compliance"]["audit_trail"]
            },
            "research_mode": self.config["research_mode"]
        }


class EthicalGuidelines:
    """
    Ethical guidelines for network monitoring research
    """
    
    @staticmethod
    def print_guidelines():
        """Print ethical guidelines for network monitoring"""
        print("\n" + "=" * 60)
        print("ETHICAL GUIDELINES FOR NETWORK MONITORING")
        print("=" * 60)
        
        print("\n1. LEGAL COMPLIANCE:")
        print("   • Only monitor networks you own or have explicit permission to monitor")
        print("   • Comply with local privacy laws (GDPR, CCPA, etc.)")
        print("   • Respect organizational policies and agreements")
        print("   • Obtain proper authorization before deployment")
        
        print("\n2. PRIVACY PROTECTION:")
        print("   • Anonymize personal identifiers (IP addresses, MAC addresses)")
        print("   • Avoid capturing sensitive payload data")
        print("   • Implement data minimization principles")
        print("   • Use encryption for stored data")
        
        print("\n3. RESEARCH ETHICS:")
        print("   • Use data only for stated research purposes")
        print("   • Obtain institutional review board (IRB) approval if required")
        print("   • Publish results responsibly without exposing vulnerabilities")
        print("   • Share findings with network owners when appropriate")
        
        print("\n4. TECHNICAL SAFEGUARDS:")
        print("   • Implement access controls and authentication")
        print("   • Use secure communication channels")
        print("   • Regular security audits and updates")
        print("   • Incident response procedures")
        
        print("\n5. RESPONSIBLE DISCLOSURE:")
        print("   • Report security vulnerabilities responsibly")
        print("   • Coordinate with affected parties")
        print("   • Allow reasonable time for fixes")
        print("   • Follow established disclosure protocols")
        
        print("\n" + "=" * 60)


def setup_secure_environment():
    """Set up secure environment for network monitoring"""
    print("Setting up secure network monitoring environment...")
    
    # Initialize security config
    security = SecurityConfig()
    
    # Show ethical guidelines
    EthicalGuidelines.print_guidelines()
    
    # Get user consent
    if not security.get_user_consent():
        print("Network monitoring cancelled - consent not granted.")
        return None
    
    # Clean up old data
    security.cleanup_old_data()
    
    # Create security report
    report = security.create_security_report()
    print(f"\nSecurity configuration validated.")
    print(f"Privacy protections: {'Enabled' if report['privacy_compliance']['ip_anonymization'] else 'Disabled'}")
    print(f"Data retention: {report['privacy_compliance']['data_retention_policy']}")
    
    return security


if __name__ == "__main__":
    setup_secure_environment()