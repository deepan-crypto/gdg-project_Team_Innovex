"""
Unsafe Model Serialization Scanner
Detects remote code execution risks from deserialization
"""

import os
import re
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict

@dataclass
class UnsafePattern:
    pattern: str
    file: str
    line_number: int
    severity: str
    description: str
    safe_alternative: str

@dataclass
class SerializationReport:
    unsafe_patterns: List[UnsafePattern]
    risk_level: str
    rce_risk: str
    recommendations: List[str]

class SerializationScanner:
    """Scans code for unsafe model deserialization"""
    
    UNSAFE_PATTERNS = {
        'pickle.load': {
            'description': 'pickle.load() deserializes arbitrary Python objects - RCE risk',
            'safe_alternative': 'Use pickle.loads() with restricted unpickler or switch to JSON',
            'severity': 'CRITICAL'
        },
        'torch.load': {
            'description': 'torch.load() without map_location can execute arbitrary code',
            'safe_alternative': 'Use torch.load(file, map_location=device) with weights_only=True',
            'severity': 'CRITICAL'
        },
        'joblib.load': {
            'description': 'joblib.load() has similar RCE risks as pickle',
            'safe_alternative': 'Use joblib.load with protocol=4 or switch serialization',
            'severity': 'HIGH'
        },
        'keras.models.load_model': {
            'description': 'May execute custom code in custom_objects',
            'safe_alternative': 'Use safe_mode=True or load from official model zoos',
            'severity': 'MEDIUM'
        }
    }
    
    def scan_directory(self, directory: str) -> SerializationReport:
        """
        Scan directory recursively for unsafe deserialization
        
        Args:
            directory: Root directory to scan
        
        Returns:
            SerializationReport with findings
        """
        unsafe_patterns = []
        
        for py_file in Path(directory).rglob('*.py'):
            patterns = self._scan_file(str(py_file))
            unsafe_patterns.extend(patterns)
        
        risk_level = self._classify_risk(unsafe_patterns)
        
        return SerializationReport(
            unsafe_patterns=unsafe_patterns,
            risk_level=risk_level,
            rce_risk=self._get_rce_explanation(unsafe_patterns),
            recommendations=self._get_recommendations(unsafe_patterns)
        )
    
    def _scan_file(self, filepath: str) -> List[UnsafePattern]:
        """Scan single Python file for unsafe patterns"""
        patterns = []
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception:
            return patterns
        
        for line_num, line in enumerate(lines, 1):
            for pattern_name, pattern_info in self.UNSAFE_PATTERNS.items():
                if re.search(rf'\b{pattern_name}\s*\(', line):
                    patterns.append(UnsafePattern(
                        pattern=pattern_name,
                        file=filepath,
                        line_number=line_num,
                        severity=pattern_info['severity'],
                        description=pattern_info['description'],
                        safe_alternative=pattern_info['safe_alternative']
                    ))
        
        return patterns
    
    def _classify_risk(self, patterns: List[UnsafePattern]) -> str:
        if not patterns:
            return "Low"
        
        critical = sum(1 for p in patterns if p.severity == 'CRITICAL')
        if critical > 0:
            return "Critical"
        
        high = sum(1 for p in patterns if p.severity == 'HIGH')
        if high > 0:
            return "High"
        
        return "Medium"
    
    def _get_rce_explanation(self, patterns: List[UnsafePattern]) -> str:
        if not patterns:
            return "No unsafe deserialization detected."
        
        return (
            "⚠️ REMOTE CODE EXECUTION RISK:\n\n"
            "Python's pickle and similar serializers can execute arbitrary code during deserialization.\n\n"
            "🎯 REAL EXPLOIT SCENARIO:\n"
            "1. Attacker creates malicious pickle file with embedded shell command\n"
            "2. Attacker tricks system to load it: model = pickle.load(open('model.pkl'))\n"
            "3. During deserialization, arbitrary code executes (e.g., exfiltrate data, install backdoor)\n"
            "4. Attacker gains full system access\n\n"
            "🛡️ This is why untrusted model files are dangerous!"
        )
    
    def _get_recommendations(self, patterns: List[UnsafePattern]) -> List[str]:
        recs = [
            "✅ Use JSON/YAML for configuration instead of pickle",
            "✅ Use torch.load(..., weights_only=True) for PyTorch models",
            "✅ Never load models from untrusted sources",
            "✅ Validate model file signatures (cryptographic signatures)",
            "✅ Use sandboxed environments for loading untrusted models",
            "✅ Switch to safer formats: ONNX, SafeTensors, Protocol Buffers"
        ]
        
        for pattern in patterns:
            if pattern.severity == 'CRITICAL':
                recs.insert(0, f"🚨 CRITICAL: Fix {pattern.pattern} usage immediately")
                break
        
        return recs
