"""
AI-Powered Threat Intelligence System
Advanced threat analysis using machine learning and pattern recognition
Author: Aryan Pravin Sahu
"""

import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
import json
import re
from collections import defaultdict, Counter
import hashlib

class ThreatIntelligenceEngine:
    """
    AI-powered threat intelligence and analysis system
    Provides intelligent threat classification, risk assessment, and attack pattern recognition
    """
    
    def __init__(self):
        self.threat_patterns = self._initialize_threat_patterns()
        self.attack_signatures = self._initialize_attack_signatures()
        self.risk_models = {}
        self.threat_history = []
        self.behavioral_baselines = {}
        
    def _initialize_threat_patterns(self) -> Dict:
        """Initialize known threat patterns and attack vectors"""
        return {
            'port_scanning': {
                'description': 'Sequential port scanning activity',
                'indicators': ['rapid_port_sequence', 'multiple_failed_connections'],
                'severity': 'medium',
                'mitigation': 'Rate limiting, IP blocking'
            },
            'ddos_attack': {
                'description': 'Distributed Denial of Service attack',
                'indicators': ['high_volume_traffic', 'multiple_sources', 'resource_exhaustion'],
                'severity': 'high',
                'mitigation': 'Traffic filtering, load balancing'
            },
            'data_exfiltration': {
                'description': 'Unauthorized data transfer',
                'indicators': ['large_outbound_transfers', 'unusual_protocols', 'off_hours_activity'],
                'severity': 'critical',
                'mitigation': 'Data loss prevention, network segmentation'
            },
            'lateral_movement': {
                'description': 'Internal network reconnaissance',
                'indicators': ['internal_scanning', 'privilege_escalation', 'credential_reuse'],
                'severity': 'high',
                'mitigation': 'Network segmentation, access controls'
            },
            'malware_communication': {
                'description': 'Command and control communication',
                'indicators': ['periodic_beacons', 'encrypted_channels', 'suspicious_domains'],
                'severity': 'critical',
                'mitigation': 'DNS filtering, traffic analysis'
            }
        }
    
    def _initialize_attack_signatures(self) -> Dict:
        """Initialize attack signatures and behavioral patterns"""
        return {
            'brute_force': {
                'pattern': 'multiple_failed_auth',
                'threshold': 10,
                'time_window': 300,  # 5 minutes
                'confidence': 0.85
            },
            'sql_injection': {
                'pattern': 'suspicious_query_patterns',
                'indicators': ['union_select', 'drop_table', 'exec_command'],
                'confidence': 0.90
            },
            'xss_attack': {
                'pattern': 'script_injection',
                'indicators': ['script_tags', 'javascript_payload'],
                'confidence': 0.80
            },
            'buffer_overflow': {
                'pattern': 'oversized_packets',
                'threshold': 1500,
                'confidence': 0.75
            }
        }
    
    def analyze_threat_intelligence(self, anomaly_data: Dict, network_context: Dict) -> Dict:
        """
        Perform comprehensive threat intelligence analysis
        
        Args:
            anomaly_data: Detected anomaly information
            network_context: Network traffic context and metadata
            
        Returns:
            Comprehensive threat analysis report
        """
        analysis_start = datetime.now()
        
        # Extract key features for analysis
        threat_features = self._extract_threat_features(anomaly_data, network_context)
        
        # Perform multi-layered analysis
        pattern_analysis = self._analyze_attack_patterns(threat_features)
        behavioral_analysis = self._analyze_behavioral_anomalies(threat_features)
        risk_assessment = self._calculate_risk_score(threat_features, pattern_analysis)
        attribution_analysis = self._perform_threat_attribution(threat_features)
        
        # Generate intelligent recommendations
        recommendations = self._generate_recommendations(
            pattern_analysis, behavioral_analysis, risk_assessment
        )
        
        # Compile comprehensive report
        intelligence_report = {
            'analysis_id': self._generate_analysis_id(anomaly_data),
            'timestamp': analysis_start.isoformat(),
            'threat_classification': self._classify_threat_type(pattern_analysis),
            'risk_score': risk_assessment['overall_score'],
            'confidence_level': risk_assessment['confidence'],
            'attack_patterns': pattern_analysis,
            'behavioral_indicators': behavioral_analysis,
            'threat_attribution': attribution_analysis,
            'impact_assessment': self._assess_potential_impact(threat_features),
            'recommendations': recommendations,
            'timeline_analysis': self._analyze_attack_timeline(threat_features),
            'related_incidents': self._find_related_incidents(threat_features),
            'analysis_duration': (datetime.now() - analysis_start).total_seconds()
        }
        
        # Store for future correlation
        self.threat_history.append(intelligence_report)
        
        return intelligence_report
    
    def _extract_threat_features(self, anomaly_data: Dict, network_context: Dict) -> Dict:
        """Extract relevant features for threat analysis"""
        features = {
            'source_ip': network_context.get('src_ip', ''),
            'destination_ip': network_context.get('dst_ip', ''),
            'source_port': network_context.get('src_port', 0),
            'destination_port': network_context.get('dst_port', 0),
            'protocol': network_context.get('protocol', ''),
            'packet_size': network_context.get('size', 0),
            'timestamp': network_context.get('timestamp', datetime.now()),
            'anomaly_confidence': anomaly_data.get('confidence', 0),
            'detection_algorithms': anomaly_data.get('detected_by', []),
            'packet_flags': network_context.get('flags', ''),
            'payload_indicators': self._analyze_payload_patterns(network_context),
            'geolocation': self._get_ip_geolocation(network_context.get('src_ip', '')),
            'reputation': self._check_ip_reputation(network_context.get('src_ip', '')),
            # Extract attack simulation data if present
            'attack_type': network_context.get('attack_type'),
            'attack_description': network_context.get('attack_description'),
            'is_simulated_attack': network_context.get('attack_type') is not None
        }
        
        return features
    
    def _analyze_attack_patterns(self, features: Dict) -> Dict:
        """Analyze for known attack patterns"""
        detected_patterns = {}
        
        # Check if packet has explicit attack type (from simulation)
        explicit_attack = features.get('attack_type')
        if explicit_attack:
            detected_patterns[explicit_attack] = {
                'confidence': 0.95,
                'indicators': ['simulation_labeled'],
                'severity': self._get_attack_severity(explicit_attack),
                'description': features.get('attack_description', f'{explicit_attack} detected')
            }
        
        # Port scanning detection
        if self._detect_port_scanning(features):
            detected_patterns['port_scanning'] = {
                'confidence': 0.85,
                'indicators': ['sequential_ports', 'syn_flags', 'small_packets'],
                'severity': 'medium',
                'description': 'Sequential port scanning activity detected'
            }
        
        # DDoS pattern detection
        if self._detect_ddos_pattern(features):
            detected_patterns['ddos_attack'] = {
                'confidence': 0.90,
                'indicators': ['high_volume', 'syn_flood', 'distributed_sources'],
                'severity': 'high',
                'description': 'Distributed denial of service attack pattern'
            }
        
        # Data exfiltration detection
        if self._detect_data_exfiltration(features):
            detected_patterns['data_exfiltration'] = {
                'confidence': 0.80,
                'indicators': ['large_transfers', 'external_destination', 'encrypted_channel'],
                'severity': 'critical',
                'description': 'Potential data exfiltration to external host'
            }
        
        # Malware communication detection
        if self._detect_malware_communication(features):
            detected_patterns['malware_communication'] = {
                'confidence': 0.75,
                'indicators': ['periodic_beacons', 'suspicious_ports', 'c2_communication'],
                'severity': 'critical',
                'description': 'Malware command and control communication'
            }
        
        return detected_patterns
    
    def _get_attack_severity(self, attack_type: str) -> str:
        """Get severity level for attack type"""
        severity_map = {
            'port_scan': 'medium',
            'ddos': 'high',
            'data_exfiltration': 'critical',
            'malware_beacon': 'critical'
        }
        return severity_map.get(attack_type, 'medium')
    
    def _analyze_behavioral_anomalies(self, features: Dict) -> Dict:
        """Analyze behavioral anomalies and deviations"""
        behavioral_indicators = {}
        
        # Time-based analysis
        timestamp = features.get('timestamp', datetime.now())
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        
        # Off-hours activity detection
        if timestamp.hour < 6 or timestamp.hour > 22:
            behavioral_indicators['off_hours_activity'] = {
                'description': 'Activity during non-business hours',
                'risk_factor': 1.3,
                'time': timestamp.strftime('%H:%M:%S')
            }
        
        # Unusual protocol usage
        protocol = features.get('protocol', '').upper()
        if protocol in ['FTP', 'TELNET', 'RLOGIN']:
            behavioral_indicators['legacy_protocol'] = {
                'description': 'Usage of legacy/insecure protocol',
                'risk_factor': 1.5,
                'protocol': protocol
            }
        
        # Suspicious port combinations
        src_port = features.get('source_port', 0)
        dst_port = features.get('destination_port', 0)
        
        if src_port > 50000 and dst_port < 1024:
            behavioral_indicators['suspicious_ports'] = {
                'description': 'High source port to privileged destination port',
                'risk_factor': 1.2,
                'ports': f"{src_port} -> {dst_port}"
            }
        
        # Large packet analysis
        packet_size = features.get('packet_size', 0)
        if packet_size > 1400:
            behavioral_indicators['oversized_packet'] = {
                'description': 'Unusually large packet size',
                'risk_factor': 1.1,
                'size': packet_size
            }
        
        return behavioral_indicators
    
    def _calculate_risk_score(self, features: Dict, patterns: Dict) -> Dict:
        """Calculate comprehensive risk score"""
        base_score = 0.0
        confidence_factors = []
        
        # Base anomaly confidence
        anomaly_confidence = features.get('anomaly_confidence', 0)
        base_score += anomaly_confidence * 30
        confidence_factors.append(anomaly_confidence)
        
        # Pattern-based scoring
        for pattern_name, pattern_data in patterns.items():
            pattern_confidence = pattern_data.get('confidence', 0)
            severity_multiplier = {
                'low': 1.0,
                'medium': 1.5,
                'high': 2.0,
                'critical': 3.0
            }.get(pattern_data.get('severity', 'low'), 1.0)
            
            base_score += pattern_confidence * 20 * severity_multiplier
            confidence_factors.append(pattern_confidence)
        
        # IP reputation factor
        reputation = features.get('reputation', {})
        if reputation.get('is_malicious', False):
            base_score += 25
            confidence_factors.append(0.9)
        
        # Geolocation risk factor
        geolocation = features.get('geolocation', {})
        if geolocation.get('is_high_risk_country', False):
            base_score += 15
            confidence_factors.append(0.7)
        
        # Normalize score to 0-100 range
        final_score = min(100, max(0, base_score))
        
        # Calculate overall confidence
        overall_confidence = np.mean(confidence_factors) if confidence_factors else 0.5
        
        return {
            'overall_score': round(final_score, 2),
            'confidence': round(overall_confidence, 3),
            'risk_level': self._categorize_risk_level(final_score),
            'score_breakdown': {
                'anomaly_base': anomaly_confidence * 30,
                'pattern_indicators': sum(p.get('confidence', 0) * 20 for p in patterns.values()),
                'reputation_factor': 25 if reputation.get('is_malicious') else 0,
                'geolocation_factor': 15 if geolocation.get('is_high_risk_country') else 0
            }
        }
    
    def _perform_threat_attribution(self, features: Dict) -> Dict:
        """Perform threat attribution analysis"""
        attribution = {
            'source_analysis': {},
            'attack_methodology': {},
            'infrastructure_analysis': {},
            'campaign_correlation': {}
        }
        
        # Source IP analysis
        src_ip = features.get('source_ip', '')
        attribution['source_analysis'] = {
            'ip_address': src_ip,
            'geolocation': features.get('geolocation', {}),
            'reputation': features.get('reputation', {}),
            'asn_info': self._get_asn_info(src_ip),
            'historical_activity': self._get_historical_activity(src_ip)
        }
        
        # Attack methodology analysis
        detection_algorithms = features.get('detection_algorithms', [])
        attribution['attack_methodology'] = {
            'detection_methods': detection_algorithms,
            'sophistication_level': self._assess_sophistication(features),
            'attack_vector': self._identify_attack_vector(features),
            'tools_techniques': self._identify_tools_techniques(features)
        }
        
        return attribution
    
    def _generate_recommendations(self, patterns: Dict, behavioral: Dict, risk: Dict) -> List[Dict]:
        """Generate intelligent security recommendations"""
        recommendations = []
        
        # High-priority recommendations based on risk score
        if risk['overall_score'] > 80:
            recommendations.append({
                'priority': 'critical',
                'action': 'immediate_isolation',
                'description': 'Immediately isolate affected systems and investigate',
                'timeline': 'immediate'
            })
        
        # Pattern-specific recommendations
        for pattern_name, pattern_data in patterns.items():
            if pattern_name in self.threat_patterns:
                threat_info = self.threat_patterns[pattern_name]
                recommendations.append({
                    'priority': threat_info['severity'],
                    'action': f'mitigate_{pattern_name}',
                    'description': threat_info['mitigation'],
                    'timeline': 'within_1_hour'
                })
        
        # Behavioral recommendations
        if 'off_hours_activity' in behavioral:
            recommendations.append({
                'priority': 'medium',
                'action': 'enhanced_monitoring',
                'description': 'Implement enhanced monitoring for off-hours activities',
                'timeline': 'within_24_hours'
            })
        
        # General security improvements
        recommendations.append({
            'priority': 'low',
            'action': 'update_signatures',
            'description': 'Update threat detection signatures based on new patterns',
            'timeline': 'within_week'
        })
        
        return recommendations
    
    def _classify_threat_type(self, patterns: Dict) -> Dict:
        """Classify the overall threat type"""
        if not patterns:
            return {
                'primary_type': 'unknown_anomaly',
                'confidence': 0.5,
                'description': 'Anomalous behavior detected but no specific threat pattern identified'
            }
        
        # Find the highest confidence pattern
        primary_pattern = max(patterns.items(), key=lambda x: x[1].get('confidence', 0))
        
        return {
            'primary_type': primary_pattern[0],
            'confidence': primary_pattern[1].get('confidence', 0),
            'description': self.threat_patterns.get(primary_pattern[0], {}).get('description', 'Unknown threat type'),
            'secondary_types': [name for name, data in patterns.items() if name != primary_pattern[0]]
        }
    
    def _assess_potential_impact(self, features: Dict) -> Dict:
        """Assess potential impact of the threat"""
        impact_assessment = {
            'confidentiality': 'low',
            'integrity': 'low',
            'availability': 'low',
            'business_impact': 'minimal',
            'affected_systems': [],
            'data_at_risk': []
        }
        
        # Assess based on destination port and protocol
        dst_port = features.get('destination_port', 0)
        protocol = features.get('protocol', '').upper()
        
        # Critical service ports
        if dst_port in [22, 23, 3389, 5900]:  # SSH, Telnet, RDP, VNC
            impact_assessment['confidentiality'] = 'high'
            impact_assessment['integrity'] = 'high'
        
        # Database ports
        if dst_port in [1433, 1521, 3306, 5432]:  # SQL Server, Oracle, MySQL, PostgreSQL
            impact_assessment['confidentiality'] = 'critical'
            impact_assessment['data_at_risk'] = ['customer_data', 'financial_records']
        
        # Web services
        if dst_port in [80, 443, 8080, 8443]:
            impact_assessment['availability'] = 'medium'
            impact_assessment['business_impact'] = 'moderate'
        
        return impact_assessment
    
    def _analyze_attack_timeline(self, features: Dict) -> Dict:
        """Analyze attack timeline and progression"""
        timestamp = features.get('timestamp', datetime.now())
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        
        return {
            'detection_time': timestamp.isoformat(),
            'estimated_start': (timestamp - timedelta(minutes=5)).isoformat(),
            'attack_duration': 'ongoing',
            'progression_stage': 'initial_detection',
            'predicted_next_steps': ['reconnaissance', 'lateral_movement', 'data_access']
        }
    
    def _find_related_incidents(self, features: Dict) -> List[Dict]:
        """Find related incidents from threat history"""
        related_incidents = []
        src_ip = features.get('source_ip', '')
        
        # Search through recent threat history
        for incident in self.threat_history[-100:]:  # Last 100 incidents
            if incident.get('threat_attribution', {}).get('source_analysis', {}).get('ip_address') == src_ip:
                related_incidents.append({
                    'incident_id': incident.get('analysis_id'),
                    'timestamp': incident.get('timestamp'),
                    'threat_type': incident.get('threat_classification', {}).get('primary_type'),
                    'risk_score': incident.get('risk_score')
                })
        
        return related_incidents[:5]  # Return top 5 related incidents
    
    # Helper methods for threat detection
    def _detect_port_scanning(self, features: Dict) -> bool:
        """Detect port scanning patterns"""
        # Check for explicit port scan attack
        if features.get('attack_type') == 'port_scan':
            return True
        
        # Heuristic detection
        src_ip = features.get('source_ip', '')
        dst_port = features.get('destination_port', 0)
        packet_size = features.get('packet_size', 0)
        flags = features.get('packet_flags', '')
        
        # External IP scanning internal network with small SYN packets
        is_external_src = not src_ip.startswith('192.168.')
        is_small_packet = packet_size < 100
        is_syn_only = flags == 'SYN'
        is_low_port = dst_port < 1024
        
        return is_external_src and is_small_packet and is_syn_only and is_low_port
    
    def _detect_ddos_pattern(self, features: Dict) -> bool:
        """Detect DDoS attack patterns"""
        # Check for explicit DDoS attack
        if features.get('attack_type') == 'ddos':
            return True
        
        # Heuristic detection
        packet_size = features.get('packet_size', 0)
        flags = features.get('packet_flags', '')
        dst_port = features.get('destination_port', 0)
        src_ip = features.get('source_ip', '')
        
        # Small packets with SYN flags targeting web services from external sources
        is_small_flood = packet_size < 100
        is_syn_flood = 'SYN' in flags
        is_web_target = dst_port in [80, 443]
        is_external_src = not src_ip.startswith('192.168.')
        
        return is_small_flood and is_syn_flood and is_web_target and is_external_src
    
    def _detect_data_exfiltration(self, features: Dict) -> bool:
        """Detect data exfiltration patterns"""
        # Check for explicit data exfiltration
        if features.get('attack_type') == 'data_exfiltration':
            return True
        
        # Heuristic detection
        packet_size = features.get('packet_size', 0)
        protocol = features.get('protocol', '').upper()
        src_ip = features.get('source_ip', '')
        dst_ip = features.get('destination_ip', '')
        dst_port = features.get('destination_port', 0)
        
        # Large packets from internal to external using encrypted protocols
        is_large_transfer = packet_size > 1200
        is_encrypted = protocol in ['HTTPS', 'SSL', 'TLS'] or dst_port == 443
        is_internal_to_external = src_ip.startswith('192.168.') and not dst_ip.startswith('192.168.')
        
        return is_large_transfer and is_encrypted and is_internal_to_external
    
    def _detect_malware_communication(self, features: Dict) -> bool:
        """Detect malware communication patterns"""
        # Check for explicit malware beacon
        if features.get('attack_type') == 'malware_beacon':
            return True
        
        # Heuristic detection
        dst_port = features.get('destination_port', 0)
        src_ip = features.get('source_ip', '')
        dst_ip = features.get('destination_ip', '')
        packet_size = features.get('packet_size', 0)
        
        # Internal host communicating with external on suspicious ports
        suspicious_ports = [4444, 5555, 6666, 8080, 9999]
        is_suspicious_port = dst_port in suspicious_ports
        is_internal_to_external = src_ip.startswith('192.168.') and not dst_ip.startswith('192.168.')
        is_beacon_size = 200 <= packet_size <= 500  # Typical beacon size
        
        return is_suspicious_port and is_internal_to_external and is_beacon_size
    
    def _analyze_payload_patterns(self, network_context: Dict) -> Dict:
        """Analyze payload for suspicious patterns"""
        return {
            'has_suspicious_strings': False,
            'encoded_content': False,
            'script_injection': False
        }
    
    def _get_ip_geolocation(self, ip_address: str) -> Dict:
        """Get IP geolocation information (simplified)"""
        # In a real implementation, this would use a geolocation service
        return {
            'country': 'Unknown',
            'region': 'Unknown',
            'is_high_risk_country': False
        }
    
    def _check_ip_reputation(self, ip_address: str) -> Dict:
        """Check IP reputation (simplified)"""
        # In a real implementation, this would use threat intelligence feeds
        return {
            'is_malicious': False,
            'reputation_score': 0.5,
            'threat_categories': []
        }
    
    def _get_asn_info(self, ip_address: str) -> Dict:
        """Get ASN information for IP address"""
        return {
            'asn': 'Unknown',
            'organization': 'Unknown',
            'is_hosting_provider': False
        }
    
    def _get_historical_activity(self, ip_address: str) -> Dict:
        """Get historical activity for IP address"""
        return {
            'first_seen': None,
            'last_seen': None,
            'total_incidents': 0,
            'attack_types': []
        }
    
    def _assess_sophistication(self, features: Dict) -> str:
        """Assess attack sophistication level"""
        # Simplified assessment
        if len(features.get('detection_algorithms', [])) > 2:
            return 'high'
        elif features.get('anomaly_confidence', 0) > 0.8:
            return 'medium'
        else:
            return 'low'
    
    def _identify_attack_vector(self, features: Dict) -> str:
        """Identify primary attack vector"""
        protocol = features.get('protocol', '').upper()
        dst_port = features.get('destination_port', 0)
        
        if protocol == 'HTTP' or protocol == 'HTTPS':
            return 'web_application'
        elif dst_port in [22, 23, 3389]:
            return 'remote_access'
        elif dst_port in [1433, 1521, 3306, 5432]:
            return 'database'
        else:
            return 'network_service'
    
    def _identify_tools_techniques(self, features: Dict) -> List[str]:
        """Identify potential tools and techniques used"""
        techniques = []
        
        if features.get('packet_size', 0) > 1400:
            techniques.append('buffer_overflow_attempt')
        
        if 'SYN' in features.get('packet_flags', ''):
            techniques.append('syn_flood')
        
        return techniques
    
    def _categorize_risk_level(self, score: float) -> str:
        """Categorize risk level based on score"""
        if score >= 80:
            return 'critical'
        elif score >= 60:
            return 'high'
        elif score >= 40:
            return 'medium'
        elif score >= 20:
            return 'low'
        else:
            return 'minimal'
    
    def _generate_analysis_id(self, anomaly_data: Dict) -> str:
        """Generate unique analysis ID"""
        timestamp = datetime.now().isoformat()
        data_hash = hashlib.md5(str(anomaly_data).encode()).hexdigest()[:8]
        return f"TI_{timestamp.replace(':', '').replace('-', '').replace('.', '')[:14]}_{data_hash}"


def demo_threat_intelligence():
    """Demo function for threat intelligence system"""
    print("Advanced Threat Intelligence System Demo")
    print("=" * 50)
    
    # Initialize threat intelligence engine
    ti_engine = ThreatIntelligenceEngine()
    
    # Sample anomaly data
    sample_anomaly = {
        'confidence': 0.85,
        'detected_by': ['isolation_forest', 'one_class_svm'],
        'packet_index': 42
    }
    
    # Sample network context
    sample_context = {
        'src_ip': '192.168.1.100',
        'dst_ip': '10.0.0.50',
        'src_port': 54321,
        'dst_port': 22,
        'protocol': 'TCP',
        'size': 1200,
        'timestamp': datetime.now().isoformat(),
        'flags': 'SYN,ACK'
    }
    
    # Perform threat intelligence analysis
    print("Performing threat intelligence analysis...")
    intelligence_report = ti_engine.analyze_threat_intelligence(sample_anomaly, sample_context)
    
    # Display results
    print(f"\nThreat Analysis Report:")
    print(f"Analysis ID: {intelligence_report['analysis_id']}")
    print(f"Risk Score: {intelligence_report['risk_score']}/100")
    print(f"Risk Level: {intelligence_report['risk_score']}")
    print(f"Confidence: {intelligence_report['confidence_level']:.3f}")
    print(f"Threat Type: {intelligence_report['threat_classification']['primary_type']}")
    
    print(f"\nDetected Patterns:")
    for pattern, data in intelligence_report['attack_patterns'].items():
        print(f"  - {pattern}: {data['confidence']:.2f} confidence")
    
    print(f"\nRecommendations:")
    for i, rec in enumerate(intelligence_report['recommendations'][:3], 1):
        print(f"  {i}. [{rec['priority'].upper()}] {rec['description']}")
    
    print(f"\nAnalysis completed in {intelligence_report['analysis_duration']:.3f} seconds")
    
    return intelligence_report


if __name__ == "__main__":
    demo_threat_intelligence()