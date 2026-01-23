import re
import math
from collections import Counter

class SecretsScanner:
    """
    Detect hardcoded secrets with entropy analysis.
    
    WHY THIS IS DANGEROUS:
    If you hardcode API keys in your code and push to GitHub, anyone can:
    1. Steal your key
    2. Use YOUR cloud account to run expensive operations
    3. Access YOUR user data
    4. Delete YOUR databases
    5. Send malicious emails from YOUR account
    
    Real attack: Hacker finds AWS key in public repo, launches crypto miners,
    victim gets $10,000 bill in 24 hours.
    """
    
    PATTERNS = {
        "openai_key": {
            "pattern": r'sk-[A-Za-z0-9\-_]{48}',
            "type": "OpenAI API Key",
            "severity": "CRITICAL",
            "abuse": "Run expensive API calls on victim's account, accessing private data"
        },
        "gemini_key": {
            "pattern": r'AIza[0-9A-Za-z\-_]{35}',
            "type": "Google Gemini/Firebase Key",
            "severity": "CRITICAL",
            "abuse": "Access Firebase database, run unauthorized ML API calls"
        },
        "aws_key": {
            "pattern": r'AKIA[0-9A-Z]{16}',
            "type": "AWS Access Key",
            "severity": "CRITICAL",
            "abuse": "Launch EC2 instances, delete S3 buckets, access databases"
        },
        "aws_secret": {
            "pattern": r'aws_secret_access_key\s*=\s*["\']([A-Za-z0-9/+=]{40})["\']',
            "type": "AWS Secret Key",
            "severity": "CRITICAL",
            "abuse": "Combined with access key = full AWS account compromise"
        },
        "firebase_db": {
            "pattern": r'https://([a-z0-9-]+)\.firebaseio\.com',
            "type": "Firebase Database URL",
            "severity": "HIGH",
            "abuse": "Access real-time database if rules are misconfigured"
        },
        "github_token": {
            "pattern": r'ghp_[A-Za-z0-9_]{36}',
            "type": "GitHub Personal Token",
            "severity": "CRITICAL",
            "abuse": "Push malicious code to repos, delete repos, access private repos"
        },
        "generic_api_key": {
            "pattern": r'api[_-]?key\s*[:=]\s*["\']([A-Za-z0-9\-_]{20,})["\']',
            "type": "Generic API Key",
            "severity": "HIGH",
            "abuse": "Depends on service, but usually full account access"
        },
        "jwt_token": {
            "pattern": r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
            "type": "JWT Token",
            "severity": "HIGH",
            "abuse": "Impersonate users, bypass authentication"
        },
        "database_url": {
            "pattern": r'(mongodb|mysql|postgres)[+a-z]*://[^:\s]+:[^@\s]+@',
            "type": "Database Connection String",
            "severity": "CRITICAL",
            "abuse": "Direct database access, steal/modify all data"
        },
        "private_key": {
            "pattern": r'-----BEGIN [A-Z ]+PRIVATE KEY-----',
            "type": "Private Key File",
            "severity": "CRITICAL",
            "abuse": "Decrypt all communications, impersonate the key owner"
        }
    }
    
    ENV_FILES = {'.env', '.env.local', '.env.production', 'config.js', 
                 'settings.py', 'config.yaml', '.secrets.json'}
    
    @classmethod
    def scan(cls, repo_data):
        """Scan repository for hardcoded secrets"""
        vulnerabilities = []
        files = repo_data.get("files", {})
        
        for file_path, file_info in files.items():
            content = file_info.get("content", "")
            lines = content.split("\n")
            
            # Higher scrutiny for config files
            in_config_file = any(env_file in file_path for env_file in cls.ENV_FILES)
            
            for line_num, line in enumerate(lines, 1):
                # Skip comments
                if line.strip().startswith(("#", "//")):
                    continue
                
                for secret_name, secret_config in cls.PATTERNS.items():
                    pattern = secret_config["pattern"]
                    matches = re.finditer(pattern, line)
                    
                    for match in matches:
                        # Apply entropy check for random-looking strings
                        secret_value = match.group(1) if match.groups() else match.group(0)
                        
                        if cls._is_likely_secret(secret_value):
                            vulnerabilities.append({
                                "file": file_path,
                                "line": line_num,
                                "type": secret_config["type"],
                                "severity": secret_config["severity"],
                                "description": f"Hardcoded {secret_config['type']} detected",
                                "code_snippet": line.strip()[:80],
                                "in_config_file": in_config_file,
                                "why_dangerous": (
                                    f"ATTACKERS CAN: {secret_config['abuse']}\n\n"
                                    f"REAL EXAMPLE: Dev pushes AWS keys to GitHub. "
                                    f"Bot finds it in 5 minutes. Hacker launches $10k/month "
                                    f"crypto mining on victim's account."
                                ),
                                "fix": (
                                    "1. IMMEDIATELY rotate/delete this key\n"
                                    "2. Move to environment variables:\n"
                                    "   export OPENAI_API_KEY='your-key'\n"
                                    "3. Use in code: api_key = os.getenv('OPENAI_API_KEY')\n"
                                    "4. Add .env to .gitignore\n"
                                    "5. Use secret managers: AWS Secrets Manager, "
                                    "HashiCorp Vault, GitHub Secrets"
                                )
                            })
        
        return {
            "vulnerable": len(vulnerabilities) > 0,
            "count": len(vulnerabilities),
            "critical_count": sum(1 for v in vulnerabilities if v["severity"] == "CRITICAL"),
            "vulnerabilities": vulnerabilities
        }
    
    @staticmethod
    def _is_likely_secret(value):
        """
        Use entropy check to detect random API keys/tokens.
        Secrets have high entropy (lots of variety in characters).
        """
        if len(value) < 10:
            return False
        
        # Calculate Shannon entropy
        entropy = 0
        for count in Counter(value).values():
            probability = count / len(value)
            entropy -= probability * math.log2(probability)
        
        # High entropy (>4) indicates random string like API key
        return entropy > 4.0
