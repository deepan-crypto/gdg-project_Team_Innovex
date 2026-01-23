"""
FastAPI routes for Garak-based LLM Security Scanning

This module provides API endpoints for:
- Comprehensive LLM security scanning
- Individual scanner endpoints (DAN, encoding, latent injection, malware)
- Prompt analysis
- Response analysis
- Attack payload retrieval

Based on the Garak LLM vulnerability scanner.
Reference: https://github.com/leondz/garak
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, List, Any

from garak_integration import (
    LLMProbeScanner,
    DANDetector,
    JailbreakScanner,
    EncodingAttackScanner,
    LatentInjectionScanner,
    MalwareCodeDetector,
    PayloadManager,
    PAYLOAD_TYPES
)
from garak_integration.llm_probe_scanner import to_json

router = APIRouter(prefix="/api/v1/garak", tags=["Garak LLM Security"])


# === Request/Response Models ===

class TextScanRequest(BaseModel):
    """Request for scanning text content"""
    text: str
    file_path: Optional[str] = "input"


class PromptAnalysisRequest(BaseModel):
    """Request for analyzing a prompt"""
    prompt: str


class ResponseAnalysisRequest(BaseModel):
    """Request for analyzing an LLM response"""
    response: str


class RepoScanRequest(BaseModel):
    """Request for scanning repository files"""
    files: Dict[str, Dict[str, str]]
    repo_url: Optional[str] = "unknown"


class PayloadRequest(BaseModel):
    """Request for retrieving payloads"""
    payload_type: Optional[str] = None


# === Comprehensive Scanner Endpoints ===

@router.post("/scan/comprehensive")
async def comprehensive_scan(request: RepoScanRequest):
    """
    Perform comprehensive LLM security scan on repository files.
    
    Runs all garak-based scanners:
    - DAN/Jailbreak detection
    - Encoding attack detection
    - Latent injection detection
    - Malware code detection
    
    Returns consolidated report with OWASP LLM Top 10 mapping.
    """
    try:
        scanner = LLMProbeScanner()
        repo_data = {"files": request.files, "url": request.repo_url}
        report = scanner.scan_repository(repo_data)
        
        return {
            "status": "success",
            "repo_url": report.repo_url,
            "total_vulnerabilities": report.total_vulnerabilities,
            "severity": {
                "critical": report.critical_count,
                "high": report.high_count,
                "medium": report.medium_count,
                "low": report.low_count
            },
            "owasp_mapping": report.owasp_mapping,
            "summary": report.summary,
            "recommendations": report.recommendations,
            "scan_results": [
                {
                    "scanner": r.scanner_name,
                    "category": r.category,
                    "vulnerable": r.vulnerable,
                    "count": r.count,
                    "vulnerabilities": r.vulnerabilities[:20]  # Limit results
                }
                for r in report.scan_results
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/scan/text")
async def scan_text(request: TextScanRequest):
    """
    Scan a single text for all LLM vulnerability types.
    
    Useful for quick analysis of prompts or responses.
    """
    try:
        scanner = LLMProbeScanner()
        results = scanner.scan_text(request.text, request.file_path)
        
        return {
            "status": "success",
            "file_path": request.file_path,
            "results": {
                "jailbreak_detections": len(results["jailbreak"]),
                "encoding_detections": len(results["encoding"]),
                "latent_injection_detections": len(results["latent_injection"]),
                "malware_detections": len(results["malware"]),
                "dan_analysis": results["dan_signatures"]
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# === Prompt/Response Analysis Endpoints ===

@router.post("/analyze/prompt")
async def analyze_prompt(request: PromptAnalysisRequest):
    """
    Analyze a prompt for potential attack patterns.
    
    Checks for:
    - Jailbreak attempts (DAN, STAN, etc.)
    - Encoded instructions
    - Latent injections
    - Malware generation requests
    
    Returns threat level and recommendations.
    """
    try:
        scanner = LLMProbeScanner()
        analysis = scanner.analyze_prompt(request.prompt)
        
        return {
            "status": "success",
            "is_suspicious": analysis["is_suspicious"],
            "threat_level": analysis["threat_level"],
            "detected_patterns": analysis["detected_patterns"],
            "pattern_count": len(analysis["detected_patterns"]),
            "recommendations": analysis["recommendations"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze/response")
async def analyze_response(request: ResponseAnalysisRequest):
    """
    Analyze an LLM response for signs of successful attacks.
    
    Checks for:
    - DAN/jailbreak signatures
    - Malicious code patterns
    - Compromised behavior indicators
    
    Returns whether the response appears compromised.
    """
    try:
        scanner = LLMProbeScanner()
        analysis = scanner.analyze_response(request.response)
        
        return {
            "status": "success",
            "is_compromised": analysis["is_compromised"],
            "jailbreak_indicators": analysis["jailbreak_indicators"],
            "malicious_code": analysis["malicious_code"],
            "recommendations": analysis["recommendations"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# === Individual Scanner Endpoints ===

@router.post("/scan/jailbreak")
async def scan_jailbreak(request: RepoScanRequest):
    """
    Scan for DAN/Jailbreak patterns in repository.
    
    Detects:
    - DAN (Do Anything Now) attacks
    - STAN/DUDE variants
    - Developer mode bypasses
    - Emoji jailbreaks
    - Grandma/emotional manipulation
    """
    try:
        scanner = JailbreakScanner()
        repo_data = {"files": request.files}
        results = scanner.scan_repository(repo_data)
        
        return {
            "status": "success",
            "vulnerable": results["vulnerable"],
            "count": results["count"],
            "by_type": results.get("by_type", {}),
            "by_severity": results.get("by_severity", {}),
            "vulnerabilities": results.get("vulnerabilities", [])[:50]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/scan/encoding")
async def scan_encoding_attacks(request: RepoScanRequest):
    """
    Scan for encoding-based attacks in repository.
    
    Detects:
    - Base64 encoded injections
    - Hex encoded payloads
    - ROT13 obfuscation
    - Braille/Morse encoding
    - Unicode tag smuggling
    """
    try:
        scanner = EncodingAttackScanner()
        repo_data = {"files": request.files}
        results = scanner.scan_repository(repo_data)
        
        return {
            "status": "success",
            "vulnerable": results["vulnerable"],
            "count": results["count"],
            "total_encoded_found": results.get("total_encoded_found", 0),
            "by_encoding_type": results.get("by_encoding_type", {}),
            "vulnerabilities": results.get("vulnerabilities", [])[:50]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/scan/latent")
async def scan_latent_injection(request: RepoScanRequest):
    """
    Scan for latent/hidden prompt injections.
    
    Detects injections hidden in:
    - Resumes/CVs
    - Documents and reports
    - Emails
    - Code comments
    - Configuration files
    - Data files (JSON, YAML, CSV)
    """
    try:
        scanner = LatentInjectionScanner()
        repo_data = {"files": request.files}
        results = scanner.scan_repository(repo_data)
        
        return {
            "status": "success",
            "vulnerable": results["vulnerable"],
            "count": results["count"],
            "by_context": results.get("by_context", {}),
            "by_attack_type": results.get("by_attack_type", {}),
            "vulnerabilities": results.get("vulnerabilities", [])[:50]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/scan/malware")
async def scan_malware_code(request: RepoScanRequest):
    """
    Scan for malware code patterns.
    
    Detects:
    - Shell execution patterns
    - Privilege escalation
    - Keylogger code
    - Reverse shell patterns
    - Data exfiltration
    - Network attack code
    - Evasion techniques
    """
    try:
        detector = MalwareCodeDetector()
        repo_data = {"files": request.files}
        results = detector.scan_repository(repo_data)
        
        return {
            "status": "success",
            "vulnerable": results["vulnerable"],
            "malware_patterns_count": results["malware_patterns_count"],
            "malware_prompts_count": results["malware_prompts_count"],
            "by_type": results.get("by_type", {}),
            "by_severity": results.get("by_severity", {}),
            "malware_patterns": results.get("malware_patterns", [])[:50],
            "malware_prompts": results.get("malware_prompts", [])
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# === DAN Detection Endpoints ===

@router.post("/detect/dan")
async def detect_dan_signatures(request: TextScanRequest):
    """
    Check if text contains DAN output signatures.
    
    Useful for monitoring LLM outputs in real-time.
    """
    try:
        analysis = DANDetector.analyze_response(request.text)
        
        return {
            "status": "success",
            "is_jailbroken": analysis["is_jailbroken"],
            "signatures_found": analysis["signatures_found"],
            "signature_count": analysis["signature_count"],
            "risk_level": analysis["risk_level"],
            "recommendation": analysis["recommendation"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# === Payload Endpoints ===

@router.get("/payloads")
async def get_payloads(payload_type: Optional[str] = None):
    """
    Get attack payloads for security testing.
    
    Available types:
    - prompt_injection
    - sql_injection
    - xss
    - code_execution
    - shell_commands
    - dan_jailbreak
    - encoding_attack
    - data_exfiltration
    """
    try:
        if payload_type:
            from garak_integration.payloads import PayloadType
            try:
                ptype = PayloadType(payload_type)
                payloads = PayloadManager.to_dict(ptype)
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid payload type. Valid types: {PAYLOAD_TYPES}"
                )
        else:
            payloads = PayloadManager.to_dict()
        
        return {
            "status": "success",
            "payload_types": PAYLOAD_TYPES,
            **payloads
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/payloads/types")
async def get_payload_types():
    """Get list of available payload types"""
    return {
        "status": "success",
        "payload_types": PAYLOAD_TYPES,
        "descriptions": {
            "prompt_injection": "Classic prompt injection payloads",
            "sql_injection": "SQL injection attack strings",
            "xss": "Cross-site scripting payloads",
            "code_execution": "Python code execution payloads",
            "shell_commands": "Shell command injection payloads",
            "dan_jailbreak": "DAN and jailbreak prompts",
            "encoding_attack": "Encoded/obfuscated payloads",
            "data_exfiltration": "Training data extraction prompts"
        }
    }


@router.get("/payloads/search")
async def search_payloads(keyword: str):
    """Search payloads by keyword"""
    try:
        results = PayloadManager.search_payloads(keyword)
        
        return {
            "status": "success",
            "keyword": keyword,
            "count": len(results),
            "payloads": [
                {
                    "content": p.content[:200],
                    "type": p.payload_type.value,
                    "description": p.description,
                    "severity": p.severity
                }
                for p in results[:20]
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# === Health/Info Endpoints ===

@router.get("/health")
async def health_check():
    """Health check for garak integration"""
    return {
        "status": "healthy",
        "service": "garak-integration",
        "scanners": [
            "LLMProbeScanner",
            "JailbreakScanner",
            "EncodingAttackScanner",
            "LatentInjectionScanner",
            "MalwareCodeDetector",
            "DANDetector"
        ],
        "payload_types": PAYLOAD_TYPES
    }


@router.get("/info")
async def get_info():
    """Get information about garak integration"""
    return {
        "name": "Garak LLM Security Integration",
        "description": "LLM vulnerability scanning based on the Garak framework",
        "reference": "https://github.com/leondz/garak",
        "capabilities": {
            "prompt_analysis": "Analyze prompts for attack patterns",
            "response_analysis": "Check responses for jailbreak indicators",
            "repository_scanning": "Scan codebases for LLM vulnerabilities",
            "payload_library": "Access curated attack payloads for testing"
        },
        "owasp_coverage": [
            "LLM01: Prompt Injection",
            "LLM02: Insecure Output Handling",
            "LLM06: Sensitive Information Disclosure",
            "LLM10: Model Theft"
        ]
    }
