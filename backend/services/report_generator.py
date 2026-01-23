import json
import os
from datetime import datetime
import uuid

class ReportGenerator:
    """Generate comprehensive security reports with teaching focus"""
    
    def __init__(self, output_dir="./scan_reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def generate(self, repo_url, scan_results):
        """Generate detailed report with explanations"""
        scan_id = str(uuid.uuid4())
        
        report = {
            "scan_id": scan_id,
            "timestamp": datetime.now().isoformat(),
            "repository": repo_url,
            "summary": self._generate_summary(scan_results),
            "results": self._enhance_results(scan_results),
            "learning_guide": self._generate_learning_guide(scan_results)
        }
        
        report_path = os.path.join(self.output_dir, f"{scan_id}.json")
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)
        
        return scan_id, report_path
    
    def _enhance_results(self, results):
        """Add detailed explanations to each vulnerability"""
        enhanced = {}
        
        for scanner_name, scanner_result in results.items():
            if isinstance(scanner_result, dict):
                enhanced[scanner_name] = {
                    "summary": scanner_result.get("summary", {}),
                    "vulnerabilities": self._enhance_vulns(
                        scanner_result.get("vulnerabilities", [])
                    )
                }
        
        return enhanced
    
    @staticmethod
    def _enhance_vulns(vulns):
        """Each vuln should have What/Why/How/Fix"""
        for vuln in vulns:
            if "why_dangerous" not in vuln:
                vuln["why_dangerous"] = "Security vulnerability detected"
            
            # Structure: What is the mistake?
            vuln["what"] = vuln.get("description", "Unknown vulnerability")
            vuln["why"] = vuln.get("why_dangerous", "Unknown risk")
            vuln["how_attacked"] = vuln.get("how_attacked", "Attacker exploits this to gain unauthorized access")
            vuln["how_to_fix"] = vuln.get("fix", "Review security best practices")
        
        return vulns
    
    @staticmethod
    def _generate_learning_guide(results):
        """Generate teaching materials for each vulnerability type"""
        guide = {
            "prompt_injection": {
                "concept": "Separating trusted instructions from untrusted user input",
                "lesson": (
                    "When building LLM apps, your system prompt is like a rulebook. "
                    "User input is like customer requests. If you glue them together without "
                    "marking which is which, customers can claim to be the boss and break the rules."
                ),
                "exercise": (
                    "Write a chatbot using message roles. "
                    "Try to trick it by saying 'Ignore previous instructions'. It should ignore you!"
                )
            },
            "secrets": {
                "concept": "Separating code from sensitive configuration",
                "lesson": (
                    "Never commit API keys to git. Not 'private' repos - NEVER. "
                    "It's in git history forever. Even if you delete it, history shows it. "
                    "Use environment variables or secret managers."
                ),
                "exercise": (
                    "Take your current project. Find all hardcoded secrets. "
                    "Move them to .env. Add .env to .gitignore. "
                    "Commit. Now the keys are safe."
                )
            },
            "sql_injection": {
                "concept": "SQL is a language. User input can be commands!",
                "lesson": (
                    "When you build SQL by string concatenation, user input becomes code. "
                    "Parameterized queries put user input in a sandbox. It can NEVER be code, "
                    "only data."
                ),
                "exercise": (
                    "Vulnerable: query = f'SELECT * FROM users WHERE id={user_id}'\n"
                    "Safe: cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))\n"
                    "The ? is a placeholder. Database knows user_id is data, not code."
                )
            },
            "xss": {
                "concept": "Don't execute user input in browsers",
                "lesson": (
                    "innerHTML treats input as HTML+JavaScript. innerHTML user comments = RCE in browsers. "
                    "Use textContent (text only) or escape HTML entities."
                ),
                "exercise": (
                    "Create a comment system. Try: <img src=x onerror=alert('XSS')>\n"
                    "If it alerts, you're vulnerable. Use textContent or escaping to fix."
                )
            },
            "dependencies": {
                "concept": "You're only as secure as your dependencies",
                "lesson": (
                    "Every library you use is attack surface. Keep them updated. "
                    "Old versions have known exploits. Attackers use automated tools "
                    "to find and exploit them."
                ),
                "exercise": (
                    "Run: pip list --outdated\n"
                    "Update old packages. Test your app. "
                    "Set up automated dependency checking (Dependabot)."
                )
            }
        }
        
        return guide
    
    @staticmethod
    def _generate_summary(results):
        """Generate summary statistics"""
        total = 0
        critical = 0
        high = 0
        
        for scanner_result in results.values():
            if isinstance(scanner_result, dict) and "vulnerabilities" in scanner_result:
                vulns = scanner_result.get("vulnerabilities", [])
                total += len(vulns)
                critical += sum(1 for v in vulns if v.get("severity") == "CRITICAL")
                high += sum(1 for v in vulns if v.get("severity") == "HIGH")
        
        return {
            "total_vulnerabilities": total,
            "critical": critical,
            "high": high,
            "risk_level": (
                "CRITICAL" if critical > 0 else
                "HIGH" if high > 2 else
                "MEDIUM" if high > 0 else
                "LOW"
            ),
            "action_required": critical > 0,
            "fix_urgency": f"Fix {critical} critical issues immediately!"
        }
