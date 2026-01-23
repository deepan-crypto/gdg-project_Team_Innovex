"""
Model Extraction Risk Analyzer
Detects vulnerability to model cloning attacks
"""

from dataclasses import dataclass
from typing import List, Dict

@dataclass
class ExtractionRisk:
    risk_level: str
    risk_score: float
    vulnerabilities: List[Dict]
    attack_scenario: str
    mitigations: List[str]

class ModelExtractionAnalyzer:
    """Analyzes endpoints for model extraction vulnerability"""
    
    def analyze_endpoint(self, endpoint_config: Dict) -> ExtractionRisk:
        """
        Analyze API endpoint for extraction risks
        
        Args:
            endpoint_config: Dict with keys:
                - is_public: bool
                - has_auth: bool
                - returns_full_probs: bool
                - rate_limit: int or None
                - requires_auth_header: bool
        """
        vulnerabilities = []
        risk_score = 0.0
        
        # Check 1: Public accessibility
        if endpoint_config.get('is_public', True):
            vulnerabilities.append({
                'type': 'Public Endpoint',
                'severity': 'HIGH',
                'description': 'Model available to unauthenticated users'
            })
            risk_score += 0.3
        
        # Check 2: Authentication
        if not endpoint_config.get('has_auth', False):
            vulnerabilities.append({
                'type': 'No Authentication',
                'severity': 'CRITICAL',
                'description': 'No auth mechanism - anyone can call the endpoint'
            })
            risk_score += 0.4
        
        # Check 3: Full probability outputs
        if endpoint_config.get('returns_full_probs', False):
            vulnerabilities.append({
                'type': 'Full Softmax Output',
                'severity': 'HIGH',
                'description': 'Returning full probability distribution enables accurate model extraction'
            })
            risk_score += 0.3
        
        # Check 4: Rate limiting
        if not endpoint_config.get('rate_limit'):
            vulnerabilities.append({
                'type': 'No Rate Limiting',
                'severity': 'HIGH',
                'description': 'Unlimited requests allow attackers to query model many times'
            })
            risk_score += 0.2
        
        risk_level = self._classify_risk(min(1.0, risk_score))
        
        return ExtractionRisk(
            risk_level=risk_level,
            risk_score=min(1.0, risk_score),
            vulnerabilities=vulnerabilities,
            attack_scenario=self._get_attack_scenario(vulnerabilities),
            mitigations=self._get_mitigations(vulnerabilities)
        )
    
    def _classify_risk(self, score: float) -> str:
        if score < 0.3:
            return "Low"
        elif score < 0.6:
            return "Medium"
        else:
            return "High"
    
    def _get_attack_scenario(self, vulns: List[Dict]) -> str:
        if not vulns:
            return "No extraction risk detected."
        
        return (
            "🎯 ATTACK SCENARIO:\n"
            "1. Attacker probes your public endpoint with varied inputs\n"
            "2. Collects thousands of predictions with full probability outputs\n"
            "3. Uses these predictions to train a substitute model\n"
            "4. Substitute model mimics your model's behavior\n"
            "5. Attacker now has cloned model (intellectual property theft)"
        )
    
    def _get_mitigations(self, vulns: List[Dict]) -> List[str]:
        mitigations = [
            "✅ Require authentication (API key, OAuth)",
            "✅ Implement rate limiting (100 req/hour per user)",
            "✅ Return only top-k predictions instead of full softmax",
            "✅ Add small random noise to confidence scores",
            "✅ Monitor for extraction attempts (unusual query patterns)",
            "✅ Use differential privacy for sensitive models",
            "✅ Serve via private endpoints (VPC, firewall)"
        ]
        return mitigations
