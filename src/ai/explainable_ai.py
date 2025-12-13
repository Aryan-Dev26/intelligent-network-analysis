"""
Explainable AI System for Network Anomaly Detection
Provides interpretable explanations for ML model decisions
Author: Aryan Pravin Sahu
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Optional
import json
from datetime import datetime
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.inspection import permutation_importance
from sklearn.tree import DecisionTreeClassifier, export_text
# import shap  # Optional for advanced explanations

class ExplainableAI:
    """
    Explainable AI system that provides interpretable explanations
    for anomaly detection decisions
    """
    
    def __init__(self):
        self.feature_importance_cache = {}
        self.explanation_templates = self._initialize_explanation_templates()
        self.feature_descriptions = self._initialize_feature_descriptions()
        
    def _initialize_explanation_templates(self) -> Dict:
        """Initialize explanation templates for different anomaly types"""
        return {
            'high_confidence': {
                'template': "This packet was flagged as anomalous with {confidence:.1%} confidence because {primary_reason}. Additional factors include {secondary_reasons}.",
                'threshold': 0.8
            },
            'medium_confidence': {
                'template': "This packet shows suspicious behavior with {confidence:.1%} confidence. The main concern is {primary_reason}, though {uncertainty_note}.",
                'threshold': 0.5
            },
            'low_confidence': {
                'template': "This packet exhibits some unusual characteristics with {confidence:.1%} confidence. While {primary_reason}, this could also be normal network behavior.",
                'threshold': 0.0
            }
        }
    
    def _initialize_feature_descriptions(self) -> Dict:
        """Initialize human-readable descriptions for features"""
        return {
            'packet_size': 'packet size',
            'src_port': 'source port number',
            'dst_port': 'destination port number',
            'protocol_TCP': 'TCP protocol usage',
            'protocol_UDP': 'UDP protocol usage',
            'protocol_HTTP': 'HTTP protocol usage',
            'protocol_HTTPS': 'HTTPS protocol usage',
            'protocol_DNS': 'DNS protocol usage',
            'protocol_FTP': 'FTP protocol usage',
            'hour': 'time of day',
            'day_of_week': 'day of the week',
            'is_weekend': 'weekend timing',
            'time_delta': 'time between packets',
            'is_internal_src': 'internal source IP',
            'is_internal_dst': 'internal destination IP',
            'same_subnet': 'same network subnet',
            'is_well_known_port': 'well-known port usage',
            'is_ephemeral_port': 'ephemeral port usage',
            'large_packet': 'large packet indicator',
            'is_suspicious': 'pre-flagged as suspicious',
            'size_rolling_mean': 'average recent packet size',
            'size_rolling_std': 'packet size variability',
            'num_flags': 'number of TCP flags',
            'has_syn': 'SYN flag present',
            'has_ack': 'ACK flag present',
            'has_rst': 'RST flag present'
        }
    
    def explain_anomaly_decision(self, 
                                model_results: Dict, 
                                feature_values: np.ndarray, 
                                feature_names: List[str],
                                model_type: str = 'ensemble') -> Dict:
        """
        Generate comprehensive explanation for anomaly detection decision
        
        Args:
            model_results: Results from anomaly detection models
            feature_values: Feature values for the specific instance
            feature_names: Names of the features
            model_type: Type of model used for detection
            
        Returns:
            Comprehensive explanation dictionary
        """
        
        explanation_start = datetime.now()
        
        # Calculate feature contributions
        feature_contributions = self._calculate_feature_contributions(
            model_results, feature_values, feature_names
        )
        
        # Generate natural language explanation
        natural_explanation = self._generate_natural_explanation(
            model_results, feature_contributions, feature_names
        )
        
        # Create visual explanation data
        visual_explanation = self._create_visual_explanation_data(
            feature_contributions, feature_names
        )
        
        # Generate counterfactual explanations
        counterfactuals = self._generate_counterfactual_explanations(
            feature_values, feature_names, model_results
        )
        
        # Assess explanation confidence
        explanation_confidence = self._assess_explanation_confidence(
            model_results, feature_contributions
        )
        
        # Compile comprehensive explanation
        explanation = {
            'explanation_id': self._generate_explanation_id(),
            'timestamp': explanation_start.isoformat(),
            'model_decision': {
                'is_anomaly': model_results.get('ensemble_prediction', [-1])[0] == -1,
                'confidence_score': model_results.get('confidence_scores', [0])[0],
                'contributing_models': model_results.get('individual_predictions', {}).keys()
            },
            'natural_language': natural_explanation,
            'feature_analysis': {
                'top_contributing_features': self._get_top_features(feature_contributions, 5),
                'feature_contributions': feature_contributions,
                'unusual_values': self._identify_unusual_values(feature_values, feature_names)
            },
            'visual_explanation': visual_explanation,
            'counterfactual_analysis': counterfactuals,
            'explanation_confidence': explanation_confidence,
            'technical_details': {
                'model_type': model_type,
                'feature_count': len(feature_names),
                'detection_algorithms': list(model_results.get('individual_predictions', {}).keys())
            },
            'generation_time': (datetime.now() - explanation_start).total_seconds()
        }
        
        return explanation
    
    def _calculate_feature_contributions(self, 
                                       model_results: Dict, 
                                       feature_values: np.ndarray, 
                                       feature_names: List[str]) -> Dict:
        """Calculate how much each feature contributed to the anomaly decision"""
        
        contributions = {}
        
        # For ensemble results, we'll use a simplified approach
        # In a real implementation, you'd use SHAP or LIME for more accurate attributions
        
        # Get individual model predictions
        individual_predictions = model_results.get('individual_predictions', {})
        
        # Calculate feature importance based on deviation from normal ranges
        for i, feature_name in enumerate(feature_names):
            feature_value = feature_values[i] if i < len(feature_values) else 0
            
            # Calculate contribution based on how unusual the value is
            contribution_score = self._calculate_feature_unusualness(feature_name, feature_value)
            
            contributions[feature_name] = {
                'value': float(feature_value),
                'contribution_score': contribution_score,
                'is_unusual': contribution_score > 0.5,
                'description': self.feature_descriptions.get(feature_name, feature_name)
            }
        
        return contributions
    
    def _calculate_feature_unusualness(self, feature_name: str, feature_value: float) -> float:
        """Calculate how unusual a feature value is (simplified heuristic)"""
        
        # Define normal ranges for common features (simplified)
        normal_ranges = {
            'packet_size': (64, 1500),
            'src_port': (1024, 65535),
            'dst_port': (1, 65535),
            'hour': (6, 22),  # Business hours
            'time_delta': (0.001, 1.0),
            'size_rolling_mean': (100, 800),
            'num_flags': (1, 3)
        }
        
        if feature_name in normal_ranges:
            min_val, max_val = normal_ranges[feature_name]
            
            if feature_value < min_val:
                return min(1.0, (min_val - feature_value) / min_val)
            elif feature_value > max_val:
                return min(1.0, (feature_value - max_val) / max_val)
            else:
                # Value is in normal range
                return 0.0
        
        # For binary features
        if feature_name.startswith('protocol_') or feature_name.startswith('is_') or feature_name.startswith('has_'):
            return 0.3 if feature_value > 0.5 else 0.0
        
        # Default unusualness for unknown features
        return 0.2
    
    def _generate_natural_explanation(self, 
                                    model_results: Dict, 
                                    feature_contributions: Dict, 
                                    feature_names: List[str]) -> Dict:
        """Generate natural language explanation"""
        
        confidence = model_results.get('confidence_scores', [0])[0]
        
        # Determine explanation template based on confidence
        template_key = 'low_confidence'
        if confidence >= 0.8:
            template_key = 'high_confidence'
        elif confidence >= 0.5:
            template_key = 'medium_confidence'
        
        template_info = self.explanation_templates[template_key]
        
        # Get top contributing features
        top_features = self._get_top_features(feature_contributions, 3)
        
        # Generate primary reason
        if top_features:
            primary_feature = top_features[0]
            primary_reason = self._generate_feature_explanation(
                primary_feature['name'], 
                primary_feature['contribution']
            )
        else:
            primary_reason = "multiple subtle anomalies in network behavior"
        
        # Generate secondary reasons
        secondary_reasons = []
        for feature in top_features[1:3]:
            reason = self._generate_feature_explanation(
                feature['name'], 
                feature['contribution']
            )
            secondary_reasons.append(reason)
        
        secondary_text = " and ".join(secondary_reasons) if secondary_reasons else "no additional significant factors"
        
        # Generate uncertainty note for medium confidence
        uncertainty_note = "the pattern is not entirely clear" if template_key == 'medium_confidence' else ""
        
        # Format the explanation
        explanation_text = template_info['template'].format(
            confidence=confidence,
            primary_reason=primary_reason,
            secondary_reasons=secondary_text,
            uncertainty_note=uncertainty_note
        )
        
        return {
            'summary': explanation_text,
            'confidence_level': template_key,
            'primary_factors': [primary_reason],
            'secondary_factors': secondary_reasons,
            'technical_summary': self._generate_technical_summary(model_results, top_features)
        }
    
    def _generate_feature_explanation(self, feature_name: str, contribution_data: Dict) -> str:
        """Generate explanation for a specific feature contribution"""
        
        feature_desc = contribution_data['description']
        feature_value = contribution_data['value']
        contribution_score = contribution_data['contribution_score']
        
        # Generate contextual explanations
        if feature_name == 'packet_size':
            if feature_value > 1400:
                return f"the packet size ({feature_value} bytes) is unusually large"
            elif feature_value < 64:
                return f"the packet size ({feature_value} bytes) is unusually small"
        
        elif feature_name == 'hour':
            if feature_value < 6 or feature_value > 22:
                return f"the activity occurred during off-hours ({int(feature_value)}:00)"
        
        elif feature_name.startswith('protocol_'):
            protocol = feature_name.split('_')[1]
            if feature_value > 0.5:
                return f"the use of {protocol} protocol in this context"
        
        elif feature_name == 'dst_port':
            if feature_value < 1024:
                return f"targeting a privileged port ({int(feature_value)})"
            elif feature_value in [4444, 5555, 6666]:
                return f"targeting a suspicious port ({int(feature_value)})"
        
        elif feature_name == 'time_delta':
            if feature_value < 0.001:
                return "extremely rapid packet transmission"
        
        # Generic explanation
        if contribution_score > 0.7:
            return f"highly unusual {feature_desc}"
        elif contribution_score > 0.4:
            return f"somewhat unusual {feature_desc}"
        else:
            return f"slightly abnormal {feature_desc}"
    
    def _generate_technical_summary(self, model_results: Dict, top_features: List[Dict]) -> str:
        """Generate technical summary for expert users"""
        
        individual_predictions = model_results.get('individual_predictions', {})
        detecting_models = [model for model, preds in individual_predictions.items() 
                          if any(p == -1 for p in preds)]
        
        feature_names = [f['name'] for f in top_features[:3]]
        
        return (f"Anomaly detected by {len(detecting_models)} model(s): {', '.join(detecting_models)}. "
                f"Primary contributing features: {', '.join(feature_names)}.")
    
    def _get_top_features(self, feature_contributions: Dict, n: int = 5) -> List[Dict]:
        """Get top N contributing features"""
        
        features_with_scores = []
        for name, data in feature_contributions.items():
            if data['is_unusual']:
                features_with_scores.append({
                    'name': name,
                    'contribution': data,
                    'score': data['contribution_score']
                })
        
        # Sort by contribution score
        features_with_scores.sort(key=lambda x: x['score'], reverse=True)
        
        return features_with_scores[:n]
    
    def _identify_unusual_values(self, feature_values: np.ndarray, feature_names: List[str]) -> List[Dict]:
        """Identify which feature values are unusual"""
        
        unusual_values = []
        
        for i, (value, name) in enumerate(zip(feature_values, feature_names)):
            unusualness = self._calculate_feature_unusualness(name, value)
            
            if unusualness > 0.3:  # Threshold for "unusual"
                unusual_values.append({
                    'feature': name,
                    'value': float(value),
                    'unusualness_score': unusualness,
                    'description': self.feature_descriptions.get(name, name)
                })
        
        return sorted(unusual_values, key=lambda x: x['unusualness_score'], reverse=True)
    
    def _create_visual_explanation_data(self, feature_contributions: Dict, feature_names: List[str]) -> Dict:
        """Create data for visual explanations"""
        
        # Prepare data for feature importance plot
        feature_importance_data = []
        for name, data in feature_contributions.items():
            if data['is_unusual']:
                feature_importance_data.append({
                    'feature': data['description'],
                    'importance': data['contribution_score'],
                    'value': data['value']
                })
        
        # Sort by importance
        feature_importance_data.sort(key=lambda x: x['importance'], reverse=True)
        
        return {
            'feature_importance': feature_importance_data[:10],  # Top 10 features
            'chart_type': 'horizontal_bar',
            'title': 'Feature Contributions to Anomaly Detection',
            'x_label': 'Contribution Score',
            'y_label': 'Features'
        }
    
    def _generate_counterfactual_explanations(self, 
                                            feature_values: np.ndarray, 
                                            feature_names: List[str], 
                                            model_results: Dict) -> Dict:
        """Generate counterfactual explanations (what would make this normal)"""
        
        counterfactuals = []
        
        # For each unusual feature, suggest what normal value would be
        for i, (value, name) in enumerate(zip(feature_values, feature_names)):
            unusualness = self._calculate_feature_unusualness(name, value)
            
            if unusualness > 0.5:
                normal_suggestion = self._suggest_normal_value(name, value)
                if normal_suggestion:
                    counterfactuals.append({
                        'feature': name,
                        'current_value': float(value),
                        'suggested_normal_value': normal_suggestion['value'],
                        'explanation': normal_suggestion['explanation']
                    })
        
        return {
            'suggestions': counterfactuals[:5],  # Top 5 suggestions
            'summary': f"To appear normal, this packet would need changes to {len(counterfactuals)} feature(s)"
        }
    
    def _suggest_normal_value(self, feature_name: str, current_value: float) -> Optional[Dict]:
        """Suggest what a normal value would be for a feature"""
        
        normal_ranges = {
            'packet_size': (200, 800, "typical web traffic packet size"),
            'hour': (9, 17, "business hours"),
            'dst_port': (80, 443, "standard web ports"),
            'time_delta': (0.01, 0.1, "normal inter-packet timing")
        }
        
        if feature_name in normal_ranges:
            min_val, max_val, explanation = normal_ranges[feature_name]
            suggested_value = (min_val + max_val) / 2  # Middle of normal range
            
            return {
                'value': suggested_value,
                'explanation': f"should be in range {min_val}-{max_val} ({explanation})"
            }
        
        return None
    
    def _assess_explanation_confidence(self, model_results: Dict, feature_contributions: Dict) -> Dict:
        """Assess confidence in the explanation itself"""
        
        model_confidence = model_results.get('confidence_scores', [0])[0]
        
        # Count how many features have clear contributions
        clear_contributors = sum(1 for data in feature_contributions.values() 
                               if data['contribution_score'] > 0.5)
        
        # Calculate explanation confidence
        if clear_contributors >= 3 and model_confidence > 0.8:
            explanation_confidence = 'high'
            confidence_score = 0.9
        elif clear_contributors >= 2 and model_confidence > 0.6:
            explanation_confidence = 'medium'
            confidence_score = 0.7
        else:
            explanation_confidence = 'low'
            confidence_score = 0.5
        
        return {
            'level': explanation_confidence,
            'score': confidence_score,
            'reasoning': f"Based on {clear_contributors} clear contributing features and {model_confidence:.1%} model confidence"
        }
    
    def _generate_explanation_id(self) -> str:
        """Generate unique explanation ID"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        return f"EXP_{timestamp}"
    
    def generate_explanation_report(self, explanation: Dict) -> str:
        """Generate a formatted explanation report"""
        
        report = []
        report.append("ANOMALY DETECTION EXPLANATION REPORT")
        report.append("=" * 50)
        report.append(f"Explanation ID: {explanation['explanation_id']}")
        report.append(f"Timestamp: {explanation['timestamp']}")
        report.append("")
        
        # Model decision
        decision = explanation['model_decision']
        report.append("MODEL DECISION:")
        report.append(f"  Anomaly Detected: {'Yes' if decision['is_anomaly'] else 'No'}")
        report.append(f"  Confidence Score: {decision['confidence_score']:.3f}")
        report.append(f"  Contributing Models: {', '.join(decision['contributing_models'])}")
        report.append("")
        
        # Natural language explanation
        nl_explanation = explanation['natural_language']
        report.append("EXPLANATION:")
        report.append(f"  {nl_explanation['summary']}")
        report.append("")
        
        # Top contributing features
        report.append("TOP CONTRIBUTING FEATURES:")
        for i, feature in enumerate(explanation['feature_analysis']['top_contributing_features'][:5], 1):
            contrib = feature['contribution']
            report.append(f"  {i}. {contrib['description']}: {contrib['value']} "
                         f"(contribution: {contrib['contribution_score']:.3f})")
        report.append("")
        
        # Counterfactual suggestions
        if explanation['counterfactual_analysis']['suggestions']:
            report.append("TO APPEAR NORMAL:")
            for suggestion in explanation['counterfactual_analysis']['suggestions'][:3]:
                report.append(f"  - {suggestion['feature']}: {suggestion['explanation']}")
        report.append("")
        
        # Technical details
        tech = explanation['technical_details']
        report.append("TECHNICAL DETAILS:")
        report.append(f"  Model Type: {tech['model_type']}")
        report.append(f"  Features Analyzed: {tech['feature_count']}")
        report.append(f"  Detection Algorithms: {', '.join(tech['detection_algorithms'])}")
        report.append("")
        
        # Explanation confidence
        exp_conf = explanation['explanation_confidence']
        report.append("EXPLANATION CONFIDENCE:")
        report.append(f"  Level: {exp_conf['level'].upper()}")
        report.append(f"  Score: {exp_conf['score']:.3f}")
        report.append(f"  Reasoning: {exp_conf['reasoning']}")
        
        return "\n".join(report)


def demo_explainable_ai():
    """Demo function for explainable AI system"""
    print("Explainable AI System Demo")
    print("=" * 40)
    
    # Initialize explainable AI system
    explainer = ExplainableAI()
    
    # Sample model results (simulated)
    sample_model_results = {
        'ensemble_prediction': np.array([-1]),  # Anomaly detected
        'confidence_scores': np.array([0.85]),
        'individual_predictions': {
            'isolation_forest': np.array([-1]),
            'one_class_svm': np.array([-1]),
            'dbscan': np.array([1])
        }
    }
    
    # Sample feature values and names
    feature_names = [
        'packet_size', 'src_port', 'dst_port', 'protocol_TCP', 'protocol_HTTP',
        'hour', 'is_weekend', 'time_delta', 'is_internal_src', 'large_packet'
    ]
    
    feature_values = np.array([1600, 54321, 22, 1, 0, 23, 0, 0.0005, 1, 1])
    
    # Generate explanation
    print("Generating explanation for anomaly detection...")
    explanation = explainer.explain_anomaly_decision(
        sample_model_results, feature_values, feature_names
    )
    
    # Generate and display report
    report = explainer.generate_explanation_report(explanation)
    print("\n" + report)
    
    return explanation


if __name__ == "__main__":
    demo_explainable_ai()