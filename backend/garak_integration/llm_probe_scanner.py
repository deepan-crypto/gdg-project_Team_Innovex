"""
LLM Probe Scanner - Comprehensive LLM Security Testing

This module provides a unified interface to all garak-based scanners
for comprehensive LLM security analysis of repositories.

It combines:
- Prompt injection detection
- DAN/Jailbreak detection  
- Encoding attack detection
- Latent injection detection
- Malware code detection

Based on the Garak LLM vulnerability scanner.
Reference: https://github.com/leondz/garak
"""

from dataclasses import dataclass
from typing import List, Dict, Optional, Any
from enum import Enum
import json

from .payloads import PayloadManager, PayloadType
from .dan_detector import DANDetector, JailbreakScanner
from .encoding_attacks import EncodingAttackScanner
from .latent_injection import LatentInjectionScanner
from .malware_detector import MalwareCodeDetector


class VulnerabilityCategory(Enum):
    """Categories of LLM vulnerabilities (OWASP LLM Top 10)"""
    LLM01_PROMPT_INJECTION = "LLM01: Prompt Injection"
    LLM02_INSECURE_OUTPUT = "LLM02: Insecure Output Handling"
    LLM03_TRAINING_DATA = "LLM03: Training Data Poisoning"
    LLM04_MODEL_DOS = "LLM04: Model Denial of Service"
    LLM05_SUPPLY_CHAIN = "LLM05: Supply Chain Vulnerabilities"
    LLM06_SENSITIVE_INFO = "LLM06: Sensitive Information Disclosure"
    LLM07_PLUGIN_DESIGN = "LLM07: Insecure Plugin Design"
    LLM08_EXCESSIVE_AGENCY = "LLM08: Excessive Agency"
    LLM09_OVERRELIANCE = "LLM09: Overreliance"
    LLM10_MODEL_THEFT = "LLM10: Model Theft"


@dataclass
class ScanResult:
    """Result from a security scan"""
    category: str
    scanner_name: str
    vulnerable: bool
    count: int
    severity_breakdown: Dict[str, int]
    vulnerabilities: List[Dict]
    recommendations: List[str]


@dataclass
class ComprehensiveScanReport:
    """Complete scan report across all scanners"""
    repo_url: str
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    scan_results: List[ScanResult]
    owasp_mapping: Dict[str, int]
    summary: str
    recommendations: List[str]


class LLMProbeScanner:
    """
    Comprehensive LLM security scanner combining all garak-based detection.
    
    This scanner analyzes repositories for:
    1. Prompt injection vulnerabilities
    2. DAN/Jailbreak patterns
    3. Encoding-based attacks
    4. Latent/hidden injections
    5. Malware code patterns
    
    Usage:
        scanner = LLMProbeScanner()
        report = scanner.scan_repository(repo_data)
    """
    
    def __init__(self):
        self.jailbreak_scanner = JailbreakScanner()
        self.encoding_scanner = EncodingAttackScanner()
        self.latent_scanner = LatentInjectionScanner()
        self.malware_detector = MalwareCodeDetector()
        self.dan_detector = DANDetector()
        self.payload_manager = PayloadManager()
    
    def scan_repository(self, repo_data: Dict) -> ComprehensiveScanReport:
        """
        Perform comprehensive security scan on repository.
        
        Args:
            repo_data: Dictionary with 'files' key containing file data
            
        Returns:
            ComprehensiveScanReport with all findings
        """
        scan_results = []
        
        # Run jailbreak scanner
        jailbreak_result = self.jailbreak_scanner.scan_repository(repo_data)
        scan_results.append(ScanResult(
            category=VulnerabilityCategory.LLM01_PROMPT_INJECTION.value,
            scanner_name="DAN/Jailbreak Scanner",
            vulnerable=jailbreak_result["vulnerable"],
            count=jailbreak_result["count"],
            severity_breakdown=jailbreak_result.get("by_severity", {}),
            vulnerabilities=jailbreak_result.get("vulnerabilities", []),
            recommendations=[
                "Implement input filtering for DAN patterns",
                "Add output monitoring for jailbreak signatures",
                "Use a safety classifier on responses"
            ]
        ))
        
        # Run encoding attack scanner
        encoding_result = self.encoding_scanner.scan_repository(repo_data)
        scan_results.append(ScanResult(
            category=VulnerabilityCategory.LLM01_PROMPT_INJECTION.value,
            scanner_name="Encoding Attack Scanner",
            vulnerable=encoding_result["vulnerable"],
            count=encoding_result["count"],
            severity_breakdown=encoding_result.get("by_encoding_type", {}),
            vulnerabilities=encoding_result.get("vulnerabilities", []),
            recommendations=[
                "Decode and normalize all input before LLM processing",
                "Strip invisible Unicode characters",
                "Apply content filtering after decoding"
            ]
        ))
        
        # Run latent injection scanner
        latent_result = self.latent_scanner.scan_repository(repo_data)
        scan_results.append(ScanResult(
            category=VulnerabilityCategory.LLM01_PROMPT_INJECTION.value,
            scanner_name="Latent Injection Scanner",
            vulnerable=latent_result["vulnerable"],
            count=latent_result["count"],
            severity_breakdown=latent_result.get("by_context", {}),
            vulnerabilities=latent_result.get("vulnerabilities", []),
            recommendations=[
                "Sanitize documents before LLM processing",
                "Use structured prompts separating instructions from data",
                "Implement output validation"
            ]
        ))
        
        # Run malware detector
        malware_result = self.malware_detector.scan_repository(repo_data)
        scan_results.append(ScanResult(
            category=VulnerabilityCategory.LLM02_INSECURE_OUTPUT.value,
            scanner_name="Malware Code Detector",
            vulnerable=malware_result["vulnerable"],
            count=malware_result["malware_patterns_count"],
            severity_breakdown=malware_result.get("by_severity", {}),
            vulnerabilities=malware_result.get("malware_patterns", []),
            recommendations=[
                "Review and remove any malicious code patterns",
                "Implement code review for security-sensitive functions",
                "Use static analysis in CI/CD pipeline"
            ]
        ))
        
        # Calculate totals
        total_vulns = sum(r.count for r in scan_results)
        severity_totals = self._aggregate_severity(scan_results)
        owasp_mapping = self._map_to_owasp(scan_results)
        
        return ComprehensiveScanReport(
            repo_url=repo_data.get("url", "unknown"),
            total_vulnerabilities=total_vulns,
            critical_count=severity_totals.get("CRITICAL", 0),
            high_count=severity_totals.get("HIGH", 0),
            medium_count=severity_totals.get("MEDIUM", 0),
            low_count=severity_totals.get("LOW", 0),
            scan_results=scan_results,
            owasp_mapping=owasp_mapping,
            summary=self._generate_summary(total_vulns, severity_totals),
            recommendations=self._get_top_recommendations(scan_results)
        )
    
    def scan_text(self, text: str, file_path: str = "input") -> Dict:
        """
        Scan a single text for all vulnerability types.
        
        Args:
            text: Text content to scan
            file_path: Optional file path for context
            
        Returns:
            Dictionary with all scan results
        """
        return {
            "jailbreak": self.jailbreak_scanner.scan_text(text, file_path),
            "encoding": self.encoding_scanner.scan_text(text, file_path),
            "latent_injection": self.latent_scanner.scan_text(text, file_path),
            "malware": self.malware_detector.scan_text(text, file_path),
            "dan_signatures": self.dan_detector.analyze_response(text)
        }
    
    def analyze_prompt(self, prompt: str) -> Dict:
        """
        Analyze a prompt for potential attacks.
        
        Args:
            prompt: The prompt to analyze
            
        Returns:
            Analysis results
        """
        results = {
            "is_suspicious": False,
            "threat_level": "LOW",
            "detected_patterns": [],
            "recommendations": []
        }
        
        # Check for jailbreak patterns
        jailbreak_hits = self.jailbreak_scanner.scan_text(prompt)
        if jailbreak_hits:
            results["is_suspicious"] = True
            results["detected_patterns"].extend([
                {"type": "jailbreak", "pattern": h.pattern_name}
                for h in jailbreak_hits
            ])
        
        # Check for encoding attacks
        encoding_hits = self.encoding_scanner.scan_text(prompt)
        if encoding_hits:
            results["is_suspicious"] = True
            results["detected_patterns"].extend([
                {"type": "encoding", "encoding": h.encoding_type.value}
                for h in encoding_hits
            ])
        
        # Check for latent injections
        latent_hits = self.latent_scanner.scan_text(prompt)
        if latent_hits:
            results["is_suspicious"] = True
            results["detected_patterns"].extend([
                {"type": "latent_injection", "context": h.context.value}
                for h in latent_hits
            ])
        
        # Check for malware prompts
        malware_prompts = self.malware_detector.scan_for_malware_prompts(prompt)
        if malware_prompts:
            results["is_suspicious"] = True
            results["detected_patterns"].extend(malware_prompts)
        
        # Determine threat level
        if len(results["detected_patterns"]) >= 3:
            results["threat_level"] = "CRITICAL"
        elif len(results["detected_patterns"]) >= 2:
            results["threat_level"] = "HIGH"
        elif len(results["detected_patterns"]) >= 1:
            results["threat_level"] = "MEDIUM"
        
        # Add recommendations
        if results["is_suspicious"]:
            results["recommendations"] = [
                "Block or sanitize this prompt before sending to LLM",
                "Log this attempt for security monitoring",
                "Consider rate limiting the source"
            ]
        
        return results
    
    def analyze_response(self, response: str) -> Dict:
        """
        Analyze an LLM response for signs of successful attacks.
        
        Args:
            response: The LLM response to analyze
            
        Returns:
            Analysis results
        """
        results = {
            "is_compromised": False,
            "jailbreak_indicators": [],
            "malicious_code": [],
            "recommendations": []
        }
        
        # Check for DAN signatures
        dan_analysis = self.dan_detector.analyze_response(response)
        if dan_analysis["is_jailbroken"]:
            results["is_compromised"] = True
            results["jailbreak_indicators"] = dan_analysis["signatures_found"]
        
        # Check for malicious code in response
        malware_hits = self.malware_detector.scan_text(response)
        if malware_hits:
            results["malicious_code"] = [
                {"type": h.malware_type.value, "pattern": h.matched_pattern}
                for h in malware_hits
            ]
            if any(h.severity in ["CRITICAL", "HIGH"] for h in malware_hits):
                results["is_compromised"] = True
        
        if results["is_compromised"]:
            results["recommendations"] = [
                "Do not use this response - it may be compromised",
                "Reset the conversation/session",
                "Review the prompts that led to this response",
                "Consider blocking similar future requests"
            ]
        
        return results
    
    def get_test_payloads(self, payload_type: Optional[str] = None) -> List[Dict]:
        """
        Get test payloads for security testing.
        
        Args:
            payload_type: Optional type filter (prompt_injection, sql_injection, etc)
            
        Returns:
            List of payloads with metadata
        """
        if payload_type:
            try:
                ptype = PayloadType(payload_type)
                return self.payload_manager.to_dict(ptype)
            except ValueError:
                return {"error": f"Unknown payload type: {payload_type}"}
        
        return self.payload_manager.to_dict()
    
    def _aggregate_severity(self, results: List[ScanResult]) -> Dict[str, int]:
        """Aggregate severity counts across all scanners"""
        totals = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        
        for result in results:
            for severity, count in result.severity_breakdown.items():
                if severity.upper() in totals:
                    totals[severity.upper()] += count
        
        return totals
    
    def _map_to_owasp(self, results: List[ScanResult]) -> Dict[str, int]:
        """Map findings to OWASP LLM Top 10"""
        mapping = {cat.value: 0 for cat in VulnerabilityCategory}
        
        for result in results:
            if result.count > 0:
                mapping[result.category] = mapping.get(result.category, 0) + result.count
        
        return {k: v for k, v in mapping.items() if v > 0}
    
    def _generate_summary(self, total: int, severity: Dict[str, int]) -> str:
        """Generate human-readable summary"""
        if total == 0:
            return "No LLM security vulnerabilities detected. The repository appears safe."
        
        summary_parts = [f"Found {total} potential LLM security vulnerabilities."]
        
        if severity.get("CRITICAL", 0) > 0:
            summary_parts.append(f"⚠️ {severity['CRITICAL']} CRITICAL issues require immediate attention.")
        if severity.get("HIGH", 0) > 0:
            summary_parts.append(f"🔴 {severity['HIGH']} HIGH severity issues detected.")
        if severity.get("MEDIUM", 0) > 0:
            summary_parts.append(f"🟠 {severity['MEDIUM']} MEDIUM severity issues found.")
        if severity.get("LOW", 0) > 0:
            summary_parts.append(f"🟡 {severity['LOW']} LOW severity issues noted.")
        
        return " ".join(summary_parts)
    
    def _get_top_recommendations(self, results: List[ScanResult]) -> List[str]:
        """Get consolidated top recommendations"""
        all_recs = []
        for result in results:
            if result.vulnerable:
                all_recs.extend(result.recommendations)
        
        # Deduplicate while preserving order
        seen = set()
        unique_recs = []
        for rec in all_recs:
            if rec not in seen:
                seen.add(rec)
                unique_recs.append(rec)
        
        return unique_recs[:10]  # Top 10 recommendations


def to_json(report: ComprehensiveScanReport) -> str:
    """Convert report to JSON string"""
    return json.dumps({
        "repo_url": report.repo_url,
        "total_vulnerabilities": report.total_vulnerabilities,
        "severity_breakdown": {
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
                "vulnerabilities": r.vulnerabilities
            }
            for r in report.scan_results
        ]
    }, indent=2)
