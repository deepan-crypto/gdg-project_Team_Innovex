"""
Encoding-Based Attack Detection

Detects obfuscation and encoding-based prompt injection attacks.
Based on patterns from garak/probes/encoding.py

These attacks encode malicious instructions in formats like:
1. Base64 - Binary-to-text encoding
2. ROT13 - Simple letter substitution
3. Hex - Hexadecimal encoding
4. Braille - Unicode braille characters
5. Morse - Morse code dots and dashes
6. ASCII Smuggling - Hidden Unicode characters
7. Tag encoding - Invisible Unicode tags

Reference: https://github.com/leondz/garak/blob/main/garak/probes/encoding.py
"""

import re
import base64
import binascii
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple
from enum import Enum


class EncodingType(Enum):
    """Types of encoding attacks"""
    BASE64 = "base64"
    ROT13 = "rot13"
    HEX = "hex"
    BRAILLE = "braille"
    MORSE = "morse"
    UNICODE_TAG = "unicode_tag"
    LEETSPEAK = "leetspeak"
    REVERSE = "reverse"
    MIXED = "mixed"


@dataclass
class EncodingDetection:
    """Result of encoding attack detection"""
    encoding_type: EncodingType
    original_text: str
    decoded_text: Optional[str]
    line_number: int
    file_path: str
    severity: str
    description: str
    is_suspicious: bool
    suspicion_reason: Optional[str]


# ROT13 translation table (from garak)
ROT13_TRANS = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
)

# Braille character map (from garak/probes/encoding.py)
BRAILLE_MAP = {
    "\u2801": "a", "\u2803": "b", "\u2805": "k", "\u2807": "l",
    "\u2809": "c", "\u280A": "i", "\u280B": "f", "\u280D": "m",
    "\u280E": "s", "\u280F": "p", "\u2811": "e", "\u2813": "h",
    "\u2815": "o", "\u2817": "r", "\u2819": "d", "\u281A": "j",
    "\u281B": "g", "\u281D": "n", "\u281E": "t", "\u281F": "q",
    "\u2825": "u", "\u2827": "v", "\u282D": "x", "\u2835": "z",
    "\u283A": "w", "\u283D": "y", " ": " "
}

# Morse code map (from garak/probes/encoding.py)
MORSE_MAP = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
    "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
    "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
    ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
    "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
    "--..": "Z", ".----": "1", "..---": "2", "...--": "3",
    "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9", "-----": "0", " ": " "
}

# Leetspeak mappings
LEET_MAP = {
    "4": "a", "@": "a", "8": "b", "(": "c", "3": "e", "6": "g",
    "1": "i", "|": "i", "!": "i", "0": "o", "5": "s", "$": "s",
    "7": "t", "+": "t"
}

# Suspicious phrases that indicate attacks when decoded
SUSPICIOUS_PHRASES = [
    "ignore", "previous", "instructions", "system prompt",
    "forget", "disregard", "bypass", "override",
    "jailbreak", "dan", "hack", "admin", "password",
    "secret", "confidential", "execute", "eval",
    "import os", "subprocess", "shell"
]


class EncodingDecoder:
    """Decodes various encoding schemes"""
    
    @staticmethod
    def decode_base64(text: str) -> Optional[str]:
        """Attempt to decode base64"""
        try:
            # Remove common prefixes
            text = re.sub(r'^(base64:|b64:)', '', text, flags=re.IGNORECASE)
            # Pad if necessary
            padding = 4 - len(text) % 4
            if padding != 4:
                text += '=' * padding
            decoded = base64.b64decode(text).decode('utf-8', errors='ignore')
            # Check if result looks like readable text
            if sum(c.isalpha() or c.isspace() for c in decoded) / max(len(decoded), 1) > 0.5:
                return decoded
            return None
        except Exception:
            return None
    
    @staticmethod
    def decode_rot13(text: str) -> str:
        """Decode ROT13"""
        text = re.sub(r'^(rot13:)', '', text, flags=re.IGNORECASE)
        return text.translate(ROT13_TRANS)
    
    @staticmethod
    def decode_hex(text: str) -> Optional[str]:
        """Attempt to decode hexadecimal"""
        try:
            text = re.sub(r'^(hex:|0x)', '', text, flags=re.IGNORECASE)
            text = re.sub(r'[^0-9a-fA-F]', '', text)
            decoded = binascii.unhexlify(text).decode('utf-8', errors='ignore')
            if sum(c.isalpha() or c.isspace() for c in decoded) / max(len(decoded), 1) > 0.5:
                return decoded
            return None
        except Exception:
            return None
    
    @staticmethod
    def decode_braille(text: str) -> str:
        """Decode braille unicode characters"""
        result = []
        for char in text:
            if char in BRAILLE_MAP:
                result.append(BRAILLE_MAP[char])
            elif char == " ":
                result.append(" ")
        return ''.join(result)
    
    @staticmethod
    def decode_morse(text: str) -> str:
        """Decode morse code"""
        words = text.strip().split("  ")  # Words separated by double space
        decoded_words = []
        for word in words:
            letters = word.split(" ")
            decoded_word = ""
            for letter in letters:
                if letter in MORSE_MAP:
                    decoded_word += MORSE_MAP[letter]
            decoded_words.append(decoded_word)
        return " ".join(decoded_words)
    
    @staticmethod
    def decode_leetspeak(text: str) -> str:
        """Convert leetspeak to normal text"""
        result = []
        for char in text.lower():
            result.append(LEET_MAP.get(char, char))
        return ''.join(result)
    
    @staticmethod
    def decode_unicode_tags(text: str) -> str:
        """Decode Unicode tag characters (U+E0000 range)"""
        result = []
        for char in text:
            code = ord(char)
            if 0xE0000 <= code <= 0xE007F:
                # Convert tag to regular ASCII
                result.append(chr(code - 0xE0000))
        return ''.join(result)


class EncodingAttackScanner:
    """Scans for encoding-based attack patterns"""
    
    def __init__(self):
        self.decoder = EncodingDecoder()
        self.patterns = self._compile_patterns()
    
    def _compile_patterns(self) -> Dict[EncodingType, re.Pattern]:
        """Compile regex patterns for detecting encoded content"""
        return {
            EncodingType.BASE64: re.compile(
                r'(?:base64:|b64:)?[A-Za-z0-9+/]{20,}={0,2}',
                re.IGNORECASE
            ),
            EncodingType.HEX: re.compile(
                r'(?:hex:|0x)?[0-9a-fA-F]{20,}',
                re.IGNORECASE
            ),
            EncodingType.BRAILLE: re.compile(
                r'[\u2800-\u28FF]{10,}'
            ),
            EncodingType.MORSE: re.compile(
                r'(?:[\.\-]+\s+){5,}[\.\-]+'
            ),
            EncodingType.UNICODE_TAG: re.compile(
                r'[\U000E0000-\U000E007F]+'
            ),
            EncodingType.LEETSPEAK: re.compile(
                r'[148!|053$7+@]{3,}\w*',
                re.IGNORECASE
            ),
        }
    
    def scan_text(self, text: str, file_path: str = "unknown") -> List[EncodingDetection]:
        """Scan text for encoding attacks"""
        detections = []
        lines = text.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Check for each encoding type
            line_detections = self._check_line(line, line_num, file_path)
            detections.extend(line_detections)
        
        return detections
    
    def _check_line(self, line: str, line_num: int, file_path: str) -> List[EncodingDetection]:
        """Check a single line for encoding patterns"""
        detections = []
        
        for encoding_type, pattern in self.patterns.items():
            matches = pattern.findall(line)
            for match in matches:
                detection = self._analyze_match(
                    match, encoding_type, line_num, file_path
                )
                if detection and detection.is_suspicious:
                    detections.append(detection)
        
        return detections
    
    def _analyze_match(
        self, 
        match: str, 
        encoding_type: EncodingType,
        line_num: int,
        file_path: str
    ) -> Optional[EncodingDetection]:
        """Analyze a potential encoded string"""
        decoded = None
        suspicion_reason = None
        is_suspicious = False
        
        # Try to decode based on type
        if encoding_type == EncodingType.BASE64:
            decoded = self.decoder.decode_base64(match)
        elif encoding_type == EncodingType.HEX:
            decoded = self.decoder.decode_hex(match)
        elif encoding_type == EncodingType.ROT13:
            decoded = self.decoder.decode_rot13(match)
        elif encoding_type == EncodingType.BRAILLE:
            decoded = self.decoder.decode_braille(match)
        elif encoding_type == EncodingType.MORSE:
            decoded = self.decoder.decode_morse(match)
        elif encoding_type == EncodingType.UNICODE_TAG:
            decoded = self.decoder.decode_unicode_tags(match)
            # Unicode tags are always suspicious
            is_suspicious = True
            suspicion_reason = "Invisible Unicode tags can hide malicious instructions"
        elif encoding_type == EncodingType.LEETSPEAK:
            decoded = self.decoder.decode_leetspeak(match)
        
        # Check if decoded content is suspicious
        if decoded:
            decoded_lower = decoded.lower()
            for phrase in SUSPICIOUS_PHRASES:
                if phrase in decoded_lower:
                    is_suspicious = True
                    suspicion_reason = f"Decoded text contains suspicious phrase: '{phrase}'"
                    break
        
        if not decoded and encoding_type != EncodingType.UNICODE_TAG:
            return None
        
        return EncodingDetection(
            encoding_type=encoding_type,
            original_text=match[:100] + ("..." if len(match) > 100 else ""),
            decoded_text=decoded[:200] if decoded else None,
            line_number=line_num,
            file_path=file_path,
            severity="HIGH" if is_suspicious else "LOW",
            description=f"Detected {encoding_type.value} encoded content",
            is_suspicious=is_suspicious,
            suspicion_reason=suspicion_reason
        )
    
    def scan_repository(self, repo_data: Dict) -> Dict:
        """Scan repository for encoding attacks"""
        all_detections = []
        files = repo_data.get("files", {})
        
        relevant_extensions = (
            '.py', '.js', '.ts', '.jsx', '.tsx', '.json', 
            '.yaml', '.yml', '.txt', '.md', '.html'
        )
        
        for file_path, file_data in files.items():
            if any(file_path.endswith(ext) for ext in relevant_extensions):
                content = file_data.get("content", "")
                detections = self.scan_text(content, file_path)
                all_detections.extend(detections)
        
        # Only return suspicious findings
        suspicious = [d for d in all_detections if d.is_suspicious]
        
        return {
            "vulnerable": len(suspicious) > 0,
            "count": len(suspicious),
            "total_encoded_found": len(all_detections),
            "by_encoding_type": self._group_by_type(suspicious),
            "vulnerabilities": [
                {
                    "file": d.file_path,
                    "line": d.line_number,
                    "encoding": d.encoding_type.value,
                    "original": d.original_text,
                    "decoded": d.decoded_text,
                    "severity": d.severity,
                    "description": d.description,
                    "why_dangerous": d.suspicion_reason or self._get_danger_explanation(d.encoding_type),
                    "fix": self._get_fix_recommendation()
                }
                for d in suspicious
            ]
        }
    
    def _group_by_type(self, detections: List[EncodingDetection]) -> Dict[str, int]:
        """Group detections by encoding type"""
        result = {}
        for d in detections:
            type_name = d.encoding_type.value
            result[type_name] = result.get(type_name, 0) + 1
        return result
    
    def _get_danger_explanation(self, encoding_type: EncodingType) -> str:
        """Get danger explanation for encoding type"""
        explanations = {
            EncodingType.BASE64: (
                "Base64 encoding can hide malicious instructions from simple text filters. "
                "An LLM might decode and execute these hidden commands."
            ),
            EncodingType.ROT13: (
                "ROT13 is a simple cipher that can obfuscate attack payloads. "
                "Some LLMs can decode ROT13 and follow the hidden instructions."
            ),
            EncodingType.HEX: (
                "Hexadecimal encoding can hide shell commands or code snippets "
                "that bypass text-based security filters."
            ),
            EncodingType.BRAILLE: (
                "Braille Unicode characters look like dots but encode text. "
                "LLMs may interpret this as instructions while evading visual detection."
            ),
            EncodingType.MORSE: (
                "Morse code can encode instructions that appear as random punctuation. "
                "LLMs trained on diverse data may decode and execute these."
            ),
            EncodingType.UNICODE_TAG: (
                "Unicode tag characters (U+E0000 range) are invisible but encode ASCII. "
                "This is a serious attack vector as users cannot see the hidden content."
            ),
            EncodingType.LEETSPEAK: (
                "Leetspeak substitutions can bypass content filters looking for specific words. "
                "For example, 'h4ck' bypasses filters for 'hack'."
            ),
        }
        return explanations.get(encoding_type, "Encoded content may hide malicious instructions.")
    
    def _get_fix_recommendation(self) -> str:
        """Get fix recommendation for encoding attacks"""
        return (
            "1. Normalize and decode all input before processing with the LLM.\n"
            "2. Implement detection for common encoding patterns (base64, hex, etc.).\n"
            "3. Strip invisible Unicode characters (tag range U+E0000-U+E007F).\n"
            "4. Apply content filtering AFTER decoding, not just on raw input.\n"
            "5. Consider using a preprocessing step to detect encoded content.\n"
            "6. Log instances of encoded input for security monitoring."
        )


def detect_encoding_type(text: str) -> Optional[EncodingType]:
    """Detect the encoding type of a string"""
    # Check for base64
    if re.match(r'^[A-Za-z0-9+/]+={0,2}$', text) and len(text) % 4 == 0:
        try:
            base64.b64decode(text)
            return EncodingType.BASE64
        except Exception:
            pass
    
    # Check for hex
    if re.match(r'^[0-9a-fA-F]+$', text) and len(text) % 2 == 0:
        return EncodingType.HEX
    
    # Check for braille
    if all(0x2800 <= ord(c) <= 0x28FF or c == ' ' for c in text):
        return EncodingType.BRAILLE
    
    # Check for morse
    if re.match(r'^[\.\-\s]+$', text):
        return EncodingType.MORSE
    
    # Check for unicode tags
    if any(0xE0000 <= ord(c) <= 0xE007F for c in text):
        return EncodingType.UNICODE_TAG
    
    return None
