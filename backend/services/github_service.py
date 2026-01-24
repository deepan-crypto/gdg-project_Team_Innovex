import requests
import base64
from urllib.parse import urlparse
import re
import time

class GitHubService:
    """
    Service to interact with GitHub API.
    Handles both public and private repositories.
    
    RATE LIMITS:
    - Without token: 60 requests/hour
    - With token: 5000 requests/hour
    
    Always provide a token for production use!
    """
    
    def __init__(self, token=None):
        self.token = token
        self.base_url = "https://api.github.com"
        self.headers = {"Accept": "application/vnd.github.v3+json"}
        self.rate_limit_remaining = None
        self.rate_limit_reset = None
        
        if token:
            self.headers["Authorization"] = f"token {token}"
            print("GitHub: Using authenticated requests (5000 req/hour)")
        else:
            print("GitHub: Using unauthenticated requests (60 req/hour) - consider providing a token")
    
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
            print(f"Fetching repository: {owner}/{repo}")
            
            # Check rate limit before starting
            self._check_rate_limit()
            
            # Get repository contents recursively
            files = {}
            rate_limited = self._fetch_directory(owner, repo, "", files)
            
            print(f"Total files fetched: {len(files)}")
            
            if len(files) == 0:
                if rate_limited:
                    print("ERROR: No files fetched due to GitHub API rate limiting")
                    print("Solution: Provide a GitHub token to increase rate limit to 5000 req/hour")
                else:
                    print("Warning: No files were fetched from the repository")
            
            if self.rate_limit_remaining is not None:
                print(f"GitHub API rate limit remaining: {self.rate_limit_remaining}")
            
            return {
                "owner": owner,
                "repo": repo,
                "url": repo_url,
                "files": files,
                "rate_limited": rate_limited,
                "rate_limit_remaining": self.rate_limit_remaining
            }
        except ValueError as e:
            print(f"Invalid repository URL: {e}")
            return None
        except Exception as e:
            print(f"Error fetching repository: {e}")
            return None
    
    def _check_rate_limit(self):
        """Check current rate limit status"""
        try:
            response = requests.get(f"{self.base_url}/rate_limit", headers=self.headers, timeout=5)
            if response.status_code == 200:
                data = response.json()
                core = data.get("resources", {}).get("core", {})
                self.rate_limit_remaining = core.get("remaining", 0)
                self.rate_limit_reset = core.get("reset", 0)
                
                print(f"GitHub API rate limit: {self.rate_limit_remaining} requests remaining")
                
                if self.rate_limit_remaining < 10:
                    reset_time = time.strftime('%H:%M:%S', time.localtime(self.rate_limit_reset))
                    print(f"WARNING: Rate limit almost exhausted! Resets at {reset_time}")
        except Exception as e:
            print(f"Could not check rate limit: {e}")
    
    def _fetch_directory(self, owner, repo, path, files_dict):
        """Recursively fetch all files in repository. Returns True if rate limited."""
        url = f"{self.base_url}/repos/{owner}/{repo}/contents/{path}"
        rate_limited = False
        
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            
            # Update rate limit tracking from headers
            remaining = response.headers.get('X-RateLimit-Remaining')
            if remaining:
                self.rate_limit_remaining = int(remaining)
            
            if response.status_code == 404:
                print(f"Directory not found: {path}")
                return False
            
            # Check for rate limiting
            if response.status_code == 403:
                print(f"GitHub API rate limit exceeded or access denied for: {path}")
                print(f"Rate limit remaining: {self.rate_limit_remaining}")
                return True  # Rate limited
            
            response.raise_for_status()
            contents = response.json()
            
            # Handle single file vs directory
            if not isinstance(contents, list):
                contents = [contents]
            
            print(f"Fetching {len(contents)} items from: {path or 'root'}")
            
            for item in contents:
                if item["type"] == "file":
                    # Fetch file content
                    file_content, was_rate_limited = self._fetch_file_content(
                        owner, repo, item["path"]
                    )
                    if was_rate_limited:
                        rate_limited = True
                    if file_content is not None:
                        files_dict[item["path"]] = {
                            "content": file_content,
                            "name": item["name"]
                        }
                elif item["type"] == "dir" and not item["name"].startswith("."):
                    # Recurse into subdirectories (skip hidden dirs)
                    sub_rate_limited = self._fetch_directory(
                        owner, repo, item["path"], files_dict
                    )
                    if sub_rate_limited:
                        rate_limited = True
                        
            return rate_limited
            
        except requests.exceptions.Timeout:
            print(f"Timeout fetching directory {path}")
            return rate_limited
        except Exception as e:
            print(f"Error fetching directory {path}: {e}")
            return rate_limited
    
    def _fetch_file_content(self, owner, repo, path):
        """Fetch content of a single file. Returns (content, was_rate_limited)"""
        url = f"{self.base_url}/repos/{owner}/{repo}/contents/{path}"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=5)
            
            # Update rate limit tracking
            remaining = response.headers.get('X-RateLimit-Remaining')
            if remaining:
                self.rate_limit_remaining = int(remaining)
            
            if response.status_code == 403:
                print(f"Rate limit or access denied for file: {path}")
                return None, True  # Rate limited
            
            if response.status_code != 200:
                print(f"Failed to fetch file {path}: HTTP {response.status_code}")
                return None, False
            
            data = response.json()
            
            # Decode base64 content
            if "content" in data:
                content = base64.b64decode(data["content"]).decode("utf-8", errors="ignore")
                return content, False
            
            print(f"No content field in response for: {path}")
            return None, False
        except requests.exceptions.Timeout:
            print(f"Timeout fetching file: {path}")
            return None, False
        except Exception as e:
            print(f"Error fetching file {path}: {e}")
            return None, False
