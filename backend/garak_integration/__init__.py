"""
Garak Integration Module for LLM Security Scanning

This module integrates patterns and attack techniques from the Garak LLM 
vulnerability scanner into the security scanning platform.

Components:
- LLM Probe Payloads: Attack payloads for testing LLM vulnerabilities
- DAN/Jailbreak Detection: Detect Do-Anything-Now attacks
- Encoding Attacks: Detect obfuscation-based prompt injections
- Latent Injection: Detect hidden prompt injections in documents
- Malware Generation Detection: Detect attempts to generate malicious code

Based on: https://github.com/leondz/garak
"""

from .payloads import PayloadManager, PAYLOAD_TYPES
from .dan_detector import DANDetector, JailbreakScanner
from .encoding_attacks import EncodingAttackScanner
from .latent_injection import LatentInjectionScanner
from .malware_detector import MalwareCodeDetector
from .llm_probe_scanner import LLMProbeScanner

__all__ = [
    'PayloadManager',
    'PAYLOAD_TYPES',
    'DANDetector',
    'JailbreakScanner',
    'EncodingAttackScanner',
    'LatentInjectionScanner',
    'MalwareCodeDetector',
    'LLMProbeScanner'
]
