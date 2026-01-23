"""
Membership Inference Risk Checker
Detects training data leakage
"""

from dataclasses import dataclass
from typing import List, Dict
import numpy as np

@dataclass
class MembershipRisk:
    risk_level: str
    risk_score: float
    overfitting_indicators: List[str]
    privacy_concerns: List[str]
    recommendations: List[str]

class MembershipInferenceChecker:
    """Detects membership inference risks and training data privacy leakage"""
    
    def analyze_model_behavior(self, model_metrics: Dict) -> MembershipRisk:
        """
        Analyze model for membership inference vulnerability
        
        Args:
            model_metrics: Dict with keys:
                - train_accuracy: float (0-1)
                - test_accuracy: float (0-1)
                - train_loss: float
                - test_loss: float
                - output_confidence: list of float (avg prediction confidences)
        """
        indicators = []
        risk_score = 0.0
        
        # Check 1: Overfitting (large accuracy gap)
        train_acc = model_metrics.get('train_accuracy', 0)
        test_acc = model_metrics.get('test_accuracy', 0)
        acc_gap = train_acc - test_acc
        
        if acc_gap > 0.15:
            indicators.append(
                f"Large accuracy gap: {acc_gap:.2%} (train: {train_acc:.2%}, test: {test_acc:.2%})"
            )
            risk_score += 0.3
        
        # Check 2: High training confidence
        output_conf = model_metrics.get('output_confidence', [])
        if output_conf:
            avg_conf = np.mean(output_conf)
            if avg_conf > 0.95:
                indicators.append(
                    f"Very high average confidence ({avg_conf:.2%}) - may indicate memorization"
                )
                risk_score += 0.25
        
        # Check 3: Loss divergence
        train_loss = model_metrics.get('train_loss', 0)
        test_loss = model_metrics.get('test_loss', 0)
        if train_loss > 0 and test_loss > 0:
            loss_ratio = test_loss / train_loss
            if loss_ratio > 1.5:
                indicators.append(
                    f"Large loss gap: test/train = {loss_ratio:.2f} (possible overfitting)"
                )
                risk_score += 0.25
        
        risk_level = self._classify_risk(min(1.0, risk_score))
        
        return MembershipRisk(
            risk_level=risk_level,
            risk_score=min(1.0, risk_score),
            overfitting_indicators=indicators,
            privacy_concerns=self._get_privacy_concerns(indicators),
            recommendations=self._get_recommendations(risk_level)
        )
    
    def _classify_risk(self, score: float) -> str:
        if score < 0.25:
            return "Low"
        elif score < 0.5:
            return "Medium"
        else:
            return "High"
    
    def _get_privacy_concerns(self, indicators: List[str]) -> List[str]:
        concerns = [
            "🔓 Overfitting enables membership inference attacks",
            "🎯 Attackers can determine if specific person's data was in training set",
            "📊 This violates privacy laws (GDPR, CCPA)",
            "⚠️ Sensitive data (health, financial) is at higher risk"
        ]
        
        if indicators:
            concerns.insert(0, "✋ DETECTED: Model shows overfitting patterns")
        
        return concerns
    
    def _get_recommendations(self, risk_level: str) -> List[str]:
        base = [
            "✅ Use regularization (L1/L2, dropout)",
            "✅ Apply early stopping during training",
            "✅ Implement differential privacy",
            "✅ Validate on held-out test set",
            "✅ Monitor train/test loss ratio during training",
            "✅ Use cross-validation with multiple folds"
        ]
        
        if risk_level == "High":
            base.insert(0, "🚨 HIGH RISK: Retrain model with privacy-preserving techniques")
        
        return base
