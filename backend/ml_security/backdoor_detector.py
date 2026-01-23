"""
ML Model Backdoor Risk Detector
Educational PoC - Detects potential trojan indicators
"""

import numpy as np
from typing import Dict, List, Tuple
from dataclasses import dataclass, asdict

@dataclass
class BackdoorRisk:
    risk_score: float
    risk_level: str
    indicators: List[str]
    explanation: str
    limitations: str

class BackdoorDetector:
    """Detects potential backdoor/trojan attacks in ML models"""
    
    def __init__(self):
        self.activation_threshold = 2.5  # sigma threshold
        self.anomaly_ratio_threshold = 0.15
        
    def analyze_model(self, model_activations: Dict[str, np.ndarray]) -> BackdoorRisk:
        """
        Analyze model layer activations for backdoor indicators
        
        Args:
            model_activations: Dict of layer_name -> activation_matrix
        
        Returns:
            BackdoorRisk with score and explanation
        """
        indicators = []
        risk_scores = []
        
        # Check each layer for abnormal activation patterns
        for layer_name, activations in model_activations.items():
            layer_risk = self._analyze_layer(layer_name, activations)
            if layer_risk > 0:
                risk_scores.append(layer_risk)
                indicators.append(
                    f"Layer '{layer_name}': High activation anomaly detected"
                )
        
        # Calculate overall risk
        avg_risk = np.mean(risk_scores) if risk_scores else 0.0
        overall_risk = min(1.0, avg_risk)
        
        risk_level = self._classify_risk(overall_risk)
        explanation = self._generate_explanation(indicators, overall_risk)
        
        return BackdoorRisk(
            risk_score=float(overall_risk),
            risk_level=risk_level,
            indicators=indicators,
            explanation=explanation,
            limitations=self._get_limitations()
        )
    
    def _analyze_layer(self, layer_name: str, activations: np.ndarray) -> float:
        """Check layer for abnormal activation patterns"""
        if activations.size == 0:
            return 0.0
        
        # Flatten activations
        flat = activations.flatten()
        
        # Calculate statistics
        mean = np.mean(flat)
        std = np.std(flat)
        
        if std == 0:
            return 0.0
        
        # Find neurons with extreme activations (potential backdoor neurons)
        z_scores = np.abs((flat - mean) / std)
        anomalous = np.sum(z_scores > self.activation_threshold)
        anomaly_ratio = anomalous / len(flat)
        
        # Risk if too many anomalies
        if anomaly_ratio > self.anomaly_ratio_threshold:
            return min(1.0, anomaly_ratio * 2)
        
        return 0.0
    
    def _classify_risk(self, score: float) -> str:
        """Classify risk level"""
        if score < 0.3:
            return "Low"
        elif score < 0.6:
            return "Medium"
        else:
            return "High"
    
    def _generate_explanation(self, indicators: List[str], score: float) -> str:
        """Generate human-readable explanation"""
        if score < 0.3:
            return (
                "Model shows normal activation patterns. "
                "No obvious backdoor indicators detected."
            )
        elif score < 0.6:
            return (
                "Model shows some abnormal activation patterns that warrant investigation. "
                "Could indicate overfitting or legitimate unusual architecture design."
            )
        else:
            return (
                "⚠️ Model shows strong backdoor indicators including abnormal neuron activations. "
                "Consider: retraining with clean data, dataset validation, model interpretability analysis."
            )
    
    def _get_limitations(self) -> str:
        return (
            "🔬 EDUCATIONAL PoC LIMITATIONS:\n"
            "- Heuristic-based detection (false positives possible)\n"
            "- Requires access to internal activations\n"
            "- Backdoors can be designed to evade statistical detection\n"
            "- Not a guarantee of safety - use with other defenses\n"
            "- Best practice: validate training data, use clean datasets"
        )
