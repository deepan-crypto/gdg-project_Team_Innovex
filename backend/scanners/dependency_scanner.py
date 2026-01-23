import re
import requests
import json

class DependencyScanner:
    """
    Scan for vulnerable dependencies using Google OSV API.
    
    WHY THIS IS DANGEROUS:
    You use a library with a known security hole. Attacker exploits it.
    Even though YOU didn't write the bug, your app is compromised!
    Example: Log4j vulnerability affected millions of servers instantly.
    """
    
    OSV_API_URL = "https://api.osv.dev/v1/query"
    
    REQUIREMENT_FILES = {
        'requirements.txt': 'pip',
        'Pipfile': 'pipenv',
        'setup.py': 'pip',
        'pyproject.toml': 'poetry',
        'package.json': 'npm',
        'package-lock.json': 'npm',
        'yarn.lock': 'yarn',
        'Gemfile': 'ruby',
        'pom.xml': 'maven',
        'build.gradle': 'gradle'
    }
    
    @classmethod
    def scan(cls, repo_data):
        """Scan for vulnerable dependencies"""
        vulnerabilities = []
        files = repo_data.get("files", {})
        
        for file_path, file_info in files.items():
            for req_file, package_manager in cls.REQUIREMENT_FILES.items():
                if req_file in file_path:
                    content = file_info.get("content", "")
                    deps = cls._extract_dependencies(content, package_manager, req_file)
                    
                    for dep in deps:
                        cves = cls._query_osv(dep["name"], dep["version"], package_manager)
                        
                        for cve in cves:
                            vulnerabilities.append({
                                "file": file_path,
                                "line": dep.get("line", 0),
                                "type": "Vulnerable Dependency",
                                "severity": cls._map_severity(cve),
                                "package": dep["name"],
                                "current_version": dep["version"],
                                "cve_id": cve.get("id", "N/A"),
                                "description": cve.get("summary", "Known vulnerability"),
                                "why_dangerous": (
                                    f"Your app uses {dep['name']} v{dep['version']} which has "
                                    f"a known security flaw (CVE-{cve.get('id')}). "
                                    f"Attackers can exploit this without compromising your code! "
                                    f"Real example: Log4j vulnerability let attackers RCE "
                                    f"millions of servers just by logging special text."
                                ),
                                "fix": (
                                    f"Update to version {cve.get('affected', [{}])[0].get('ranges', [{}])[0].get('events', [{}])[0].get('fixed', 'latest')} or newer:\n"
                                    f"pip install --upgrade {dep['name']}\n"
                                    f"Then test your code to ensure compatibility."
                                )
                            })
        
        return {
            "vulnerable": len(vulnerabilities) > 0,
            "count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities
        }
    
    @staticmethod
    def _extract_dependencies(content, package_manager, file_type):
        """Extract package names and versions"""
        dependencies = []
        lines = content.split("\n")
        
        if package_manager == "pip":
            # requirements.txt: package==1.0.0
            pattern = r'^([a-zA-Z0-9\-_]+)\s*[=<>!]{1,2}\s*([a-zA-Z0-9\.\-_]+)'
            for line_num, line in enumerate(lines, 1):
                match = re.match(pattern, line.strip())
                if match:
                    dependencies.append({
                        "name": match.group(1),
                        "version": match.group(2),
                        "line": line_num
                    })
        
        elif package_manager == "npm":
            # package.json: "package": "1.0.0"
            try:
                data = json.loads(content)
                for section in ["dependencies", "devDependencies"]:
                    for pkg_name, version in data.get(section, {}).items():
                        # Remove ^ and ~ version specifiers
                        clean_version = re.sub(r'^[\^~]', '', version)
                        dependencies.append({
                            "name": pkg_name,
                            "version": clean_version
                        })
            except json.JSONDecodeError:
                pass
        
        return dependencies
    
    @staticmethod
    def _query_osv(package_name, version, ecosystem):
        """Query Google OSV API for vulnerabilities"""
        try:
            # Map ecosystem names to OSV format
            ecosystem_map = {
                "pip": "PyPI",
                "npm": "npm",
                "ruby": "RubyGems",
                "maven": "Maven"
            }
            
            payload = {
                "package": {"name": package_name, "ecosystem": ecosystem_map.get(ecosystem, ecosystem)},
                "version": version
            }
            
            response = requests.post(
                DependencyScanner.OSV_API_URL,
                json=payload,
                timeout=5
            )
            
            if response.status_code == 200:
                return response.json().get("vulns", [])
        except Exception as e:
            print(f"Error querying OSV for {package_name}: {e}")
        
        return []
    
    @staticmethod
    def _map_severity(cve):
        """Map OSV severity to our severity levels"""
        severity = cve.get("severity", "UNKNOWN").upper()
        if "CRITICAL" in severity:
            return "CRITICAL"
        elif "HIGH" in severity:
            return "HIGH"
        elif "MEDIUM" in severity:
            return "MEDIUM"
        else:
            return "LOW"
