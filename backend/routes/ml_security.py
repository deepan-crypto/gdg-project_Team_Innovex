"""
FastAPI routes for ML Security Scanner - Real-time Integration
"""

from fastapi import APIRouter, UploadFile, File, HTTPException
from typing import Optional, Dict, List
import os
import tempfile
import numpy as np

from ml_security import (
    BackdoorDetector,
    ModelExtractionAnalyzer,
    MembershipInferenceChecker,
    SerializationScanner
)
from ml_security.explainer import SecurityExplainer

router = APIRouter(prefix="/api/v1", tags=["ML Security"])

@router.post("/scan/serialization")
async def scan_serialization(request: Dict):
    """Scan repository for unsafe model serialization - Real-time"""
    try:
        repo_path = request.get('repo_path', '.')
        scanner = SerializationScanner()
        report = scanner.scan_directory(repo_path)
        
        return {
            "status": "success",
            "risk_level": report.risk_level,
            "rce_risk": report.rce_risk,
            "unsafe_patterns": [
                {
                    "pattern": p.pattern,
                    "file": p.file,
                    "line": p.line_number,
                    "severity": p.severity,
                    "description": p.description,
                    "safe_alternative": p.safe_alternative
                }
                for p in report.unsafe_patterns
            ],
            "recommendations": report.recommendations
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/scan/backdoor")
async def scan_backdoor(request: Dict):
    """Analyze model for backdoor indicators - Real-time"""
    try:
        model_activations = request.get('model_activations', {})
        
        # Convert to numpy arrays
        activations = {
            layer: np.array(acts)
            for layer, acts in model_activations.items()
        }
        
        detector = BackdoorDetector()
        risk = detector.analyze_model(activations)
        
        return {
            "risk_score": risk.risk_score,
            "risk_level": risk.risk_level,
            "indicators": risk.indicators,
            "explanation": risk.explanation,
            "limitations": risk.limitations
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/scan/extraction")
async def scan_extraction_risk(request: Dict):
    """Analyze API endpoint for model extraction risk - Real-time"""
    try:
        endpoint_config = request
        analyzer = ModelExtractionAnalyzer()
        risk = analyzer.analyze_endpoint(endpoint_config)
        
        return {
            "risk_level": risk.risk_level,
            "risk_score": risk.risk_score,
            "vulnerabilities": risk.vulnerabilities,
            "attack_scenario": risk.attack_scenario,
            "mitigations": risk.mitigations
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/scan/membership_inference")
async def scan_membership_inference(request: Dict):
    """Analyze model for membership inference risk - Real-time"""
    try:
        model_metrics = request
        checker = MembershipInferenceChecker()
        risk = checker.analyze_model_behavior(model_metrics)
        
        return {
            "risk_level": risk.risk_level,
            "risk_score": risk.risk_score,
            "overfitting_indicators": risk.overfitting_indicators,
            "privacy_concerns": risk.privacy_concerns,
            "recommendations": risk.recommendations
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/explain/{vulnerability_type}")
async def explain_vulnerability(
    vulnerability_type: str,
    level: str = "beginner"
):
    """Get explanation for security vulnerability - Real-time"""
    try:
        explanation = SecurityExplainer.explain_vulnerability(vulnerability_type, level)
        
        if "error" in explanation:
            raise HTTPException(status_code=400, detail=explanation["error"])
        
        return explanation
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/explain/{vulnerability_type}/all")
async def explain_all_levels(vulnerability_type: str):
    """Get all explanation levels for vulnerability - Real-time"""
    try:
        explanations = SecurityExplainer.get_all_explanations(vulnerability_type)
        
        if not explanations:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown vulnerability type: {vulnerability_type}"
            )
        
        return {
            "type": vulnerability_type,
            "explanations": explanations
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
