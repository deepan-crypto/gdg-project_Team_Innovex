import requests
import base64
from urllib.parse import urlparse
import re
import os

class GitHubService:
    """
    Service to interact with GitHub API.
    Handles both public and private repositories.
    """
    
    def __init__(self, token=None):
        self.token = token or os.getenv("GITHUB_TOKEN")
        self.base_url = "https://api.github.com"
        self.headers = {"Accept": "application/vnd.github.v3+json"}
        
        if self.token:
            self.headers["Authorization"] = f"token {self.token}"
    
    def parse_repo_url(self, url):
        """Extract owner and repo name from GitHub URL"""
        # Handle both https://github.com/owner/repo and github.com/owner/repo
        match = re.search(r'github\.com[:/]([^/]+)/([^/]+?)(?:\.git)?/?$', url)
        if match:
            return match.group(1), match.group(2)
        raise ValueError("Invalid GitHub repository URL")
    
    def fetch_repo(self, repo_url):
        """
        Fetch all files from repository.
        Returns dict with file paths and contents.
        """
        try:
            owner, repo = self.parse_repo_url(repo_url)
            print(f"[GitHubService] Fetching repo: {owner}/{repo}")
            
            # Get repository contents recursively
            files = {}
            self._fetch_directory(owner, repo, "", files)
            
            print(f"[GitHubService] Fetched {len(files)} files")
            
            return {
                "owner": owner,
                "repo": repo,
                "url": repo_url,
                "files": files
            }
        except Exception as e:
            print(f"[GitHubService] Error fetching repository: {e}")
            return None
    
    def _fetch_directory(self, owner, repo, path, files_dict, depth=0):
        """Recursively fetch all files in repository"""
        # Limit recursion depth to prevent infinite loops
        if depth > 10:
            print(f"[GitHubService] Max depth reached at: {path}")
            return
            
        url = f"{self.base_url}/repos/{owner}/{repo}/contents/{path}"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=15)
            
            if response.status_code == 404:
                print(f"[GitHubService] 404 for path: {path}")
                return
            
            if response.status_code == 403:
                print(f"[GitHubService] Rate limited or forbidden: {response.text}")
                return
            
            response.raise_for_status()
            contents = response.json()
            
            # Handle single file vs directory
            if not isinstance(contents, list):
                contents = [contents]
            
            for item in contents:
                if item["type"] == "file":
                    # Only fetch text files, skip binary
                    if GitHubService._is_scannable_file(item["name"]):
                        file_content = self._fetch_file_content(
                            owner, repo, item["path"]
                        )
                        if file_content is not None:
                            files_dict[item["path"]] = {
                                "content": file_content,
                                "name": item["name"]
                            }
                elif item["type"] == "dir":
                    # Skip hidden directories and common non-code directories
                    skip_dirs = {'.git', 'node_modules', '__pycache__', 'venv', '.venv', 'dist', 'build'}
                    if item["name"] not in skip_dirs and not item["name"].startswith("."):
                        self._fetch_directory(
                            owner, repo, item["path"], files_dict, depth + 1
                        )
        except requests.exceptions.Timeout:
            print(f"[GitHubService] Timeout fetching: {path}")
        except Exception as e:
            print(f"[GitHubService] Error fetching directory {path}: {e}")
    
    @staticmethod
    def _is_scannable_file(filename):
        """Check if file should be scanned (skip binary files)"""
        scannable_extensions = {
            '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.rb', '.php',
            '.go', '.rs', '.c', '.cpp', '.h', '.cs', '.swift', '.kt',
            '.yaml', '.yml', '.json', '.xml', '.toml', '.ini', '.cfg',
            '.env', '.txt', '.md', '.sh', '.bash', '.zsh', '.ps1',
            '.html', '.css', '.scss', '.sql', '.graphql'
        }
        # Check extension
        ext = '.' + filename.split('.')[-1].lower() if '.' in filename else ''
        if ext in scannable_extensions:
            return True
        # Also scan files without extension that might be config
        config_names = {'Dockerfile', 'Makefile', 'requirements', 'Gemfile', 'Procfile'}
        return filename in config_names
    
    def _fetch_file_content(self, owner, repo, path):
        """Fetch content of a single file"""
        url = f"{self.base_url}/repos/{owner}/{repo}/contents/{path}"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            
            if response.status_code != 200:
                return None
            
            data = response.json()
            
            # Decode base64 content
            if "content" in data:
                try:
                    return base64.b64decode(data["content"]).decode("utf-8", errors="ignore")
                except Exception as e:
                    print(f"[GitHubService] Error decoding {path}: {e}")
                    return None
            
            return None
        except Exception as e:
            print(f"[GitHubService] Error fetching file {path}: {e}")
            return None
